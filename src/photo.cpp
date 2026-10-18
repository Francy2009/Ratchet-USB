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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
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

// Attempts to create an in-memory anonymous file using memfd_create(2).
// Returns the fd on success, -1 on failure (caller falls back to /tmp).
int try_memfd(const std::string& ext) {
#ifdef __NR_memfd_create
  // Use the raw syscall so we compile cleanly against older glibc headers
  // that may not expose memfd_create() as a libc wrapper yet.
  const int fd = static_cast<int>(
      syscall(__NR_memfd_create, ("ratchet-photo." + ext).c_str(),
              static_cast<unsigned int>(0)));  // no MFD_CLOEXEC: child needs it
  return fd;
#else
  (void)ext;
  return -1;
#endif
}

// Clears O_CLOEXEC on `fd` so the file descriptor survives exec().
// Called only inside the child process.
void clear_cloexec(int fd) {
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags >= 0) {
    (void)::fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
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
  // ── step 1: obtain a writable file descriptor for the image ─────────────
  // Prefer an anonymous in-memory file (memfd_create) so no directory entry
  // ever appears on the filesystem.  Fall back to a mkstemp() file in /tmp
  // that is unlinked immediately after xdg-open launches the viewer.

  int img_fd = try_memfd(photo.ext);
  std::string tmp_path;           // only set when using the /tmp fallback
  bool use_memfd = (img_fd >= 0);

  if (!use_memfd) {
    // Fallback: mkstemp with the correct extension so xdg-open picks the
    // right MIME type.  mkstemps() accepts a suffix length.
    tmp_path = "/tmp/ratchet-XXXXXX." + photo.ext;
    const int suffix_len = static_cast<int>(1 + photo.ext.size());
    // mkstemps needs a writable char array.
    std::vector<char> tmpl(tmp_path.begin(), tmp_path.end());
    tmpl.push_back('\0');
    img_fd = ::mkstemps(tmpl.data(), suffix_len);
    if (img_fd < 0) {
      throw Error(std::string("cannot create temporary image file: ") +
                  std::strerror(errno));
    }
    tmp_path.assign(tmpl.data());  // mkstemps filled in the X's
    // Tighten permissions: only owner can read/write.
    (void)::fchmod(img_fd, 0600);
  }

  // ── step 2: write image bytes ────────────────────────────────────────────
  if (!write_all(img_fd, photo.bytes.data(), photo.bytes.size())) {
    const std::string msg = std::strerror(errno);
    ::close(img_fd);
    if (!tmp_path.empty()) ::unlink(tmp_path.c_str());
    throw Error("cannot write image to temporary fd: " + msg);
  }

  // For the memfd path the viewer will read from the beginning; lseek back.
  if (use_memfd) {
    (void)::lseek(img_fd, 0, SEEK_SET);
  }

  // ── step 3: build the path the child will pass to xdg-open ──────────────
  // For a memfd the path is /proc/self/fd/<N> as seen by the child process
  // after it has cleared O_CLOEXEC (so the fd survives exec).
  // For the /tmp fallback the path is the real filesystem path.
  std::string viewer_path;
  if (use_memfd) {
    viewer_path = "/proc/self/fd/" + std::to_string(img_fd);
  } else {
    viewer_path = tmp_path;
  }

  // ── step 4: fork + exec xdg-open ─────────────────────────────────────────
  // We use a simple single fork.  The child:
  //   a) clears O_CLOEXEC on img_fd (memfd path only)
  //   b) exec()s xdg-open
  // The parent waits for xdg-open to exit (it launches the viewer and exits
  // quickly, typically in < 300 ms).  Once xdg-open has exited the viewer has
  // the file open via its own fd, so the directory entry (if any) can be
  // unlinked safely.

  const pid_t pid = ::fork();
  if (pid < 0) {
    const std::string msg = std::strerror(errno);
    ::close(img_fd);
    if (!tmp_path.empty()) ::unlink(tmp_path.c_str());
    throw Error("cannot fork for image viewer: " + msg);
  }

  if (pid == 0) {
    // ── child ────────────────────────────────────────────────────────────────
    // For the memfd path: clear O_CLOEXEC so the fd survives the exec.
    if (use_memfd) {
      clear_cloexec(img_fd);
    }
    // Close every fd we don't need in the child.  The image fd stays open;
    // stdin/stdout/stderr are left for xdg-open (some implementations need
    // them for error output); everything else is CLOEXEC already.

    // Detach from the process group so the viewer does not receive terminal
    // signals aimed at ratchet-usb.
    (void)::setsid();

    ::execlp("xdg-open", "xdg-open", viewer_path.c_str(), nullptr);
    // exec only returns on failure.
    _exit(127);
  }

  // ── parent ───────────────────────────────────────────────────────────────
  // Wait for xdg-open.  It exits once the viewer is launched, so this blocks
  // for at most a few hundred milliseconds.
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}

  // The image fd is no longer needed in the parent.
  ::close(img_fd);

  // Unlink the /tmp file (if used): the viewer already has it open, so the
  // file data persists until the viewer closes it.
  if (!tmp_path.empty()) {
    (void)::unlink(tmp_path.c_str());
  }

  // Report failure only when xdg-open could not be found at all (exit 127).
  if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
    throw Error(
        "image viewer could not be launched (xdg-open not found); "
        "install xdg-utils or open the image manually");
  }
}

}  // namespace ratchet::photo
