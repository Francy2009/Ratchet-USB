// photo.cpp — encrypted image support for Ratchet-USB.
//
// Images are encrypted by exactly the same Double/Triple Ratchet pipeline
// that protects text messages; this module only frames the raw bytes so the
// receiver can tell them apart from text before presenting the correct UI.
//
// See include/ratchet/photo.hpp for the wire contract.

#include "ratchet/photo.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ratchet/secure.hpp"

namespace ratchet::photo {
namespace {

// ── magic-byte tables ────────────────────────────────────────────────────────

// JPEG: FF D8 FF (first 3 bytes)
constexpr uint8_t kJpegMagic[] = {0xFF, 0xD8, 0xFF};
// PNG:  89 50 4E 47 0D 0A 1A 0A (all 8 bytes)
constexpr uint8_t kPngMagic[]  = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

bool starts_with(const std::vector<uint8_t>& buf,
                 const uint8_t* magic, std::size_t len) {
  if (buf.size() < len) return false;
  return std::memcmp(buf.data(), magic, len) == 0;
}

// ── serialisation helpers ────────────────────────────────────────────────────

void put_u32_le(std::string& out, uint32_t v) {
  out.push_back(static_cast<char>(v & 0xFFu));
  out.push_back(static_cast<char>((v >>  8) & 0xFFu));
  out.push_back(static_cast<char>((v >> 16) & 0xFFu));
  out.push_back(static_cast<char>((v >> 24) & 0xFFu));
}

uint32_t get_u32_le(const unsigned char* p) {
  return static_cast<uint32_t>(p[0])
       | (static_cast<uint32_t>(p[1]) <<  8)
       | (static_cast<uint32_t>(p[2]) << 16)
       | (static_cast<uint32_t>(p[3]) << 24);
}

// ── viewer launch helpers ────────────────────────────────────────────────────

// Writes all `size` bytes from `data` into `fd`.
// Returns false and sets errno on failure.
bool write_all(int fd, const uint8_t* data, std::size_t size) {
  while (size > 0) {
    const ssize_t n = ::write(fd, data, size);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    data += n;
    size -= static_cast<std::size_t>(n);
  }
  return true;
}

// Where a decrypted image is staged before the viewer is handed its path.
//
// $XDG_RUNTIME_DIR is a per-user tmpfs that the session clears at logout, so
// the bytes never reach durable storage. /tmp is the fallback when the
// variable is unset or unusable (a bare ssh session, say).
std::string staging_directory() {
  const char* runtime = std::getenv("XDG_RUNTIME_DIR");
  if (runtime != nullptr && runtime[0] != '\0') {
    struct stat st{};
    if (::stat(runtime, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == ::geteuid()) {
      return std::string(runtime);
    }
  }
  return "/tmp";
}

// Removes `path` after `delay_seconds` from a process detached from ours, so
// the caller never blocks on it and no zombie is left behind.
//
// The file cannot be unlinked as soon as xdg-open returns: xdg-open only asks
// the desktop to open the path and may exit before the viewer has read it, so
// an immediate unlink races the viewer. The grace period lets the viewer open
// the file; after that only an already-open descriptor keeps the data alive.
void schedule_staged_image_cleanup(const std::string& path,
                                   unsigned delay_seconds) {
  const pid_t child = ::fork();
  if (child < 0) {
    return;  // cannot clean up; the image stays staged
  }
  if (child == 0) {
    (void)::setsid();
    // Detach from the caller's terminal and pipes. A background sleeper that
    // keeps their write ends open would make a script waiting on our stdout
    // hang until the grace period ends.
    const int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      (void)::dup2(devnull, STDIN_FILENO);
      (void)::dup2(devnull, STDOUT_FILENO);
      (void)::dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO) {
        ::close(devnull);
      }
    }
    // Second fork so the sleeper is reparented to init and reaped there.
    const pid_t grandchild = ::fork();
    if (grandchild == 0) {
      ::sleep(delay_seconds);
      ::unlink(path.c_str());
    }
    _exit(0);
  }
  int status = 0;
  while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
}

}  // namespace

// ── public API ───────────────────────────────────────────────────────────────

std::vector<uint8_t> load_image(const std::filesystem::path& path) {
  // Open via openat on the parent directory so symlink attacks cannot redirect
  // the read to a different file between stat and open.
  const int dir_fd = ::open(path.parent_path().c_str(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) {
    throw Error("cannot open image directory: " +
                std::string(std::strerror(errno)));
  }

  const std::string name = path.filename().string();
  const int fd = ::openat(dir_fd, name.c_str(),
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  const int saved_errno = errno;
  ::close(dir_fd);
  if (fd < 0) {
    errno = saved_errno;
    throw Error("cannot open image file '" + path.string() + "': " +
                std::strerror(errno));
  }

  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const std::string msg = std::strerror(errno);
    ::close(fd);
    throw Error("cannot stat image file: " + msg);
  }
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    throw Error("image path is not a regular file");
  }
  if (st.st_uid != ::geteuid()) {
    ::close(fd);
    throw Error("image file is not owned by the current user");
  }

  const auto size = static_cast<std::size_t>(st.st_size);
  if (size == 0) {
    ::close(fd);
    throw Error("image file is empty");
  }
  if (size > kMaxImageBytes) {
    ::close(fd);
    throw Error("image file exceeds the 4 MiB limit");
  }

  std::vector<uint8_t> buf(size);
  std::size_t got = 0;
  while (got < size) {
    const ssize_t n = ::read(fd, buf.data() + got, size - got);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      ::close(fd);
      throw Error("short read on image file");
    }
    got += static_cast<std::size_t>(n);
  }
  ::close(fd);

  // Validate magic bytes before returning.
  (void)extension_for(buf);  // throws Error on unknown format
  return buf;
}

std::string_view extension_for(const std::vector<uint8_t>& raw) {
  if (starts_with(raw, kJpegMagic, sizeof kJpegMagic)) return "jpg";
  if (starts_with(raw, kPngMagic,  sizeof kPngMagic))  return "png";
  throw Error(
      "unsupported image format: only JPEG (FF D8 FF) and PNG "
      "(89 50 4E 47 0D 0A 1A 0A) are accepted");
}

std::string encode_photo_payload(const std::vector<uint8_t>& raw,
                                 std::string_view ext) {
  if (ext.empty() || ext.size() > 16) {
    throw Error("internal: invalid extension in encode_photo_payload");
  }
  if (raw.empty()) {
    throw Error("internal: empty image in encode_photo_payload");
  }

  std::string payload;
  payload.reserve(1 + 4 + ext.size() + raw.size());

  // Type byte
  payload.push_back(static_cast<char>(kPayloadTypeImage));
  // Extension length (u32 LE)
  put_u32_le(payload, static_cast<uint32_t>(ext.size()));
  // Extension characters
  payload.append(ext.data(), ext.size());
  // Raw image bytes
  payload.append(reinterpret_cast<const char*>(raw.data()), raw.size());

  return payload;
}

std::optional<PhotoPayload> decode_photo_payload(const std::string& plaintext) {
  if (plaintext.empty() ||
      static_cast<uint8_t>(plaintext[0]) != kPayloadTypeImage) {
    return std::nullopt;
  }

  // Minimum: type(1) + ext_len(4) + ext(≥1) + data(≥1) = 7 bytes
  const auto* p = reinterpret_cast<const unsigned char*>(plaintext.data());
  const std::size_t total = plaintext.size();

  if (total < 7) {
    throw Error("image payload is too short to be valid");
  }

  const uint32_t ext_len = get_u32_le(p + 1);
  if (ext_len == 0 || ext_len > 16) {
    throw Error("image payload has an invalid extension length");
  }
  if (total < 1u + 4u + ext_len + 1u) {
    throw Error("image payload is truncated (extension or body missing)");
  }

  PhotoPayload out;
  out.ext.assign(reinterpret_cast<const char*>(p + 5), ext_len);
  const std::size_t body_start = 5 + ext_len;
  out.bytes.assign(p + body_start, p + total);
  return out;
}

void open_photo_in_viewer(const PhotoPayload& photo) {
  // The viewer is launched by the desktop, usually as a separate -- and often
  // sandboxed -- process through xdg-desktop-portal. It does not inherit our
  // file descriptors, so passing it a /proc/self/fd/<N> path (as a memfd-based
  // earlier version did) only works when the viewer happens to be a direct
  // child; on GNOME the path resolves to an unrelated descriptor in the viewer
  // and the image cannot be read. Stage the bytes at a real path on a private
  // tmpfs and hand that path over instead.

  // ── step 1: stage the image at a real path ──────────────────────────────
  std::string path =
      staging_directory() + "/ratchet-photo-XXXXXX." + photo.ext;
  const int suffix_len = static_cast<int>(1 + photo.ext.size());
  std::vector<char> tmpl(path.begin(), path.end());
  tmpl.push_back('\0');

  // O_CLOEXEC: the viewer opens the path itself and has no business holding
  // this descriptor. mkostemps creates the file 0600; fchmod makes that
  // independent of the umask.
  const int img_fd = ::mkostemps(tmpl.data(), suffix_len, O_CLOEXEC);
  if (img_fd < 0) {
    throw Error(std::string("cannot create temporary image file: ") +
                std::strerror(errno));
  }
  path.assign(tmpl.data());  // mkostemps filled in the X's
  (void)::fchmod(img_fd, 0600);

  // ── step 2: write image bytes ────────────────────────────────────────────
  if (!write_all(img_fd, photo.bytes.data(), photo.bytes.size())) {
    const std::string msg = std::strerror(errno);
    ::close(img_fd);
    (void)::unlink(path.c_str());
    throw Error("cannot write image to temporary file: " + msg);
  }
  ::close(img_fd);

  // ── step 3: fork + exec xdg-open ─────────────────────────────────────────
  const pid_t pid = ::fork();
  if (pid < 0) {
    const std::string msg = std::strerror(errno);
    (void)::unlink(path.c_str());
    throw Error("cannot fork for image viewer: " + msg);
  }

  if (pid == 0) {
    // ── child ──────────────────────────────────────────────────────────────
    // Detach from the process group so the viewer does not receive terminal
    // signals aimed at ratchet-usb, then hand the path to the desktop.
    (void)::setsid();
    ::execlp("xdg-open", "xdg-open", path.c_str(), nullptr);
    _exit(127);  // exec only returns on failure
  }

  // ── step 4: wait, then schedule the staged file for cleanup ──────────────
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }

  // xdg-open returns as soon as it has asked the desktop to open the path,
  // which is not necessarily after the viewer has read it, so the file must
  // outlive this call. A detached helper removes it once the viewer has had
  // time to open it.
  schedule_staged_image_cleanup(path, 300);

  // Report failure only when xdg-open could not be found at all (exit 127).
  if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
    throw Error(
        "image viewer could not be launched (xdg-open not found); "
        "install xdg-utils or open the image manually");
  }
}

}  // namespace ratchet::photo
