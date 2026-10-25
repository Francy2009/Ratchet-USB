// file.cpp — encrypted file sharing for Ratchet-USB.
//
// Files are encrypted by exactly the same Double/Triple Ratchet pipeline that
// protects text messages; this module only frames the raw bytes so the receiver
// can tell them apart from text before presenting the correct UI.
//
// See include/ratchet/file.hpp for the wire contract.

#include "ratchet/file.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "ratchet/secure.hpp"

namespace ratchet::file {
namespace {

// ── magic-byte tables ────────────────────────────────────────────────────────

// JPEG: FF D8 FF (first 3 bytes)
constexpr uint8_t kJpegMagic[] = {0xFF, 0xD8, 0xFF};
// PNG:  89 50 4E 47 0D 0A 1A 0A (all 8 bytes)
constexpr uint8_t kPngMagic[]  = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

// The longest extension the wire format carries (encode and decode both refuse
// more). Kept here so sanitising and framing agree on one number.
constexpr std::size_t kMaxExtensionLength = 16;

bool starts_with(const std::vector<uint8_t>& buf,
                 const uint8_t* magic, std::size_t len) {
  if (buf.size() < len) return false;
  return std::memcmp(buf.data(), magic, len) == 0;
}

// Reduces an extension to the safe alphabet the wire format allows: a leading
// dot is dropped, letters are lowercased, anything outside [a-z0-9] is removed,
// and the result is capped at kMaxExtensionLength. An empty result means the
// caller should fall back to "bin".
//
// This is not only cosmetic. decode_file_payload() feeds the extension into a
// temporary file name, so an unsanitised value such as "../../x" from a hostile
// sender would otherwise escape the staging directory.
std::string sanitized_extension(std::string_view ext) {
  if (!ext.empty() && ext.front() == '.') {
    ext.remove_prefix(1);
  }
  std::string out;
  out.reserve(ext.size());
  for (char c : ext) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      out.push_back(c);
    }
    if (out.size() == kMaxExtensionLength) {
      break;
    }
  }
  return out;
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

// ── staging directory and its cleanup ───────────────────────────────────────

// The shortest a staged folder is kept before it may be removed. A caller that
// exits at once -- the `recv` command opens the folder and returns -- would
// otherwise take it away before the desktop has drawn it. An interface session
// lasts longer than this, so it only ever applies to that one-shot path.
constexpr unsigned kStagingMinSeconds = 300;

// Removes every regular file in `dir`, then the directory itself. The staging
// directory only ever holds files this program created, so no recursion into
// subdirectories is needed.
void remove_staging_directory(const std::string& dir) {
  DIR* d = ::opendir(dir.c_str());
  if (d != nullptr) {
    struct dirent* entry = nullptr;
    while ((entry = ::readdir(d)) != nullptr) {
      const char* name = entry->d_name;
      if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) {
        continue;
      }
      char path[4096];
      const int n = std::snprintf(path, sizeof path, "%s/%s", dir.c_str(), name);
      if (n > 0 && static_cast<std::size_t>(n) < sizeof path) {
        (void)::unlink(path);
      }
    }
    (void)::closedir(d);
  }
  (void)::rmdir(dir.c_str());
}

// The write ends of the reaper pipes, held open for the whole life of the
// process. The reaper sees end-of-file only when these close -- at exit, or by
// the kernel if the process is killed -- which is what ties the cleanup to
// closing ratchet-usb rather than to a fixed delay.
std::vector<int> g_reaper_write_fds;

// The staging directory, empty until it is created. A front end removes it
// synchronously as it exits, and the reaper repeats the removal (harmlessly)
// if the process dies without reaching that path.
std::string g_staging_dir;
bool g_exit_hook_installed = false;

void remove_staging_on_exit() {
  if (!g_staging_dir.empty()) {
    remove_staging_directory(g_staging_dir);
  }
}

// True if `dir` holds any entry other than "." and "..".
bool staging_directory_has_files(const std::string& dir) {
  DIR* d = ::opendir(dir.c_str());
  if (d == nullptr) {
    return false;
  }
  bool found = false;
  struct dirent* entry = nullptr;
  while ((entry = ::readdir(d)) != nullptr) {
    const char* name = entry->d_name;
    if (std::strcmp(name, ".") != 0 && std::strcmp(name, "..") != 0) {
      found = true;
      break;
    }
  }
  (void)::closedir(d);
  return found;
}

// Spawns a detached helper that removes `dir` once this process is gone. A pipe
// is the link between them: the helper blocks on read() and is woken by
// end-of-file when the process's write end closes. It waits out whatever part
// of kStagingMinSeconds has not yet passed, so a one-shot caller still gives
// the desktop time to open the folder, and then removes it.
//
// Returns false when the helper could not be created, so the caller can fall
// back to removing the directory on the way out.
bool start_staging_reaper(const std::string& dir) {
  int fds[2];
  if (::pipe(fds) != 0) {
    return false;
  }
  // The write end is close-on-exec so the helpers we fork later (xdg-open, the
  // clipboard) do not inherit it and keep the reaper alive past our exit.
  (void)::fcntl(fds[0], F_SETFD, FD_CLOEXEC);
  (void)::fcntl(fds[1], F_SETFD, FD_CLOEXEC);

  const pid_t child = ::fork();
  if (child < 0) {
    ::close(fds[0]);
    ::close(fds[1]);
    return false;
  }
  if (child == 0) {
    // ── the reaper ──────────────────────────────────────────────────────────
    ::close(fds[1]);
    (void)::setsid();
    // Detach from the caller's terminal and pipes, or a script waiting on our
    // stdout would hang until the folder is gone.
    const int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      (void)::dup2(devnull, STDIN_FILENO);
      (void)::dup2(devnull, STDOUT_FILENO);
      (void)::dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO) {
        ::close(devnull);
      }
    }
    const std::time_t started = std::time(nullptr);
    char byte = 0;
    // Blocks until the process's write end is closed -- at exit, or by the
    // kernel if it crashes. Only end-of-file leaves this loop.
    while (::read(fds[0], &byte, 1) > 0) {
    }
    ::close(fds[0]);
    // The grace period only matters when a file is actually there for the
    // desktop to draw; an empty folder is removed at once.
    if (staging_directory_has_files(dir)) {
      const std::time_t elapsed = std::time(nullptr) - started;
      if (elapsed < static_cast<std::time_t>(kStagingMinSeconds)) {
        ::sleep(kStagingMinSeconds - static_cast<unsigned>(elapsed));
      }
    }
    remove_staging_directory(dir);
    _exit(0);
  }

  ::close(fds[0]);
  g_reaper_write_fds.push_back(fds[1]);
  return true;
}

// Where a decrypted file is staged before the desktop is handed its folder.
//
// $XDG_RUNTIME_DIR is a per-user tmpfs that the session clears at logout, so
// the plaintext never reaches durable storage. When it is unset or unusable (a
// bare ssh session, say) a private 0700 directory is created with mkdtemp()
// under $TMPDIR (or /tmp) instead, so the plaintext is never world-readable
// even on a host whose /tmp is a real disk. The directory is created once per
// process and removed when the process exits.
const std::string& staging_directory() {
  static const std::string dir = [] {
    std::string base;
    const char* runtime = std::getenv("XDG_RUNTIME_DIR");
    if (runtime != nullptr && runtime[0] != '\0') {
      struct stat st{};
      if (::stat(runtime, &st) == 0 && S_ISDIR(st.st_mode) &&
          st.st_uid == ::geteuid()) {
        base = runtime;
      }
    }
    if (base.empty()) {
      const char* tmp = std::getenv("TMPDIR");
      base = (tmp != nullptr && tmp[0] != '\0') ? tmp : "/tmp";
    }
    std::string tmpl = base + "/ratchet-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    const char* made = ::mkdtemp(buf.data());
    if (made == nullptr) {
      // No private directory could be created. Falling back to `base` itself
      // would make cleanup treat a shared directory such as /tmp as ours and
      // delete its contents, so staging is refused instead.
      return std::string();
    }
    const std::string created(made);
    g_staging_dir = created;
    if (!start_staging_reaper(created)) {
      // No detached helper: remove the directory as the process exits. A
      // one-shot caller will show it only for an instant, but a missing helper
      // must not be allowed to leave the plaintext behind.
      if (!g_exit_hook_installed) {
        (void)std::atexit(remove_staging_on_exit);
        g_exit_hook_installed = true;
      }
    }
    return created;
  }();
  return dir;
}

}  // namespace

// ── public API ───────────────────────────────────────────────────────────────

void prepare_staging() {
  // Creating the directory is what starts the reaper; the returned path is not
  // needed here.
  (void)staging_directory();
}

void cleanup_staging() {
  // Synchronous and idempotent: a front end calls this as it exits so the
  // folder is gone the moment ratchet-usb closes, without waiting for the
  // detached reaper (which a session teardown may kill, and which otherwise
  // keeps a one-shot `recv` folder alive for its grace period).
  if (!g_staging_dir.empty()) {
    remove_staging_directory(g_staging_dir);
  }
}

std::vector<uint8_t> load_file(const std::filesystem::path& path) {
  // Open via openat on the parent directory so symlink attacks cannot redirect
  // the read to a different file between stat and open. A bare name such as
  // "note.txt" has an empty parent_path(), which would make open("") fail with
  // ENOENT, so it is read relative to the current directory instead.
  const std::filesystem::path parent =
      path.parent_path().empty() ? std::filesystem::path(".")
                                 : path.parent_path();
  const int dir_fd = ::open(parent.c_str(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) {
    throw Error("cannot open file directory: " +
                std::string(std::strerror(errno)));
  }

  const std::string name = path.filename().string();
  // O_NONBLOCK so that opening a FIFO does not block before the S_ISREG check
  // below can reject it; it is ignored for the regular files that are accepted.
  const int fd = ::openat(dir_fd, name.c_str(),
                           O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  const int saved_errno = errno;
  ::close(dir_fd);
  if (fd < 0) {
    errno = saved_errno;
    throw Error("cannot open file '" + path.string() + "': " +
                std::strerror(errno));
  }

  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const std::string msg = std::strerror(errno);
    ::close(fd);
    throw Error("cannot stat file: " + msg);
  }
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    throw Error("file path is not a regular file");
  }
  if (st.st_uid != ::geteuid()) {
    ::close(fd);
    throw Error("file is not owned by the current user");
  }

  const auto size = static_cast<std::size_t>(st.st_size);
  if (size == 0) {
    ::close(fd);
    throw Error("file is empty");
  }
  if (size > kMaxFileBytes) {
    ::close(fd);
    throw Error("file exceeds the 4 MiB limit");
  }

  std::vector<uint8_t> buf(size);
  std::size_t got = 0;
  while (got < size) {
    const ssize_t n = ::read(fd, buf.data() + got, size - got);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      ::close(fd);
      throw Error("short read on file");
    }
    got += static_cast<std::size_t>(n);
  }
  ::close(fd);
  return buf;
}

std::string extension_for(const std::filesystem::path& path,
                          const std::vector<uint8_t>& raw) {
  // An image is trusted over the name: a JPEG saved as "photo.dat" should still
  // open in the image viewer.
  if (starts_with(raw, kJpegMagic, sizeof kJpegMagic)) return "jpg";
  if (starts_with(raw, kPngMagic,  sizeof kPngMagic))  return "png";

  std::string ext = sanitized_extension(path.extension().string());
  if (ext.empty()) {
    ext = "bin";
  }
  return ext;
}

bool is_dangerous_extension(std::string_view ext) {
  // Types a desktop is liable to *run* rather than display: shell and script
  // interpreters, Windows/Linux executables, desktop entries and package
  // payloads. "bin" is deliberately absent: it is the fallback for a file whose
  // name says nothing, and a plain .bin is opened, not executed, by every
  // desktop this program targets.
  static constexpr std::string_view kDangerous[] = {
      "desktop", "sh",     "bash", "zsh",  "ksh",  "csh",  "tcsh",
      "fish",    "py",     "pyw",  "pl",   "rb",   "js",   "mjs",
      "jar",     "class",  "exe",  "com",  "bat",  "cmd",  "scr",
      "vbs",     "vbe",    "ps1",  "psm1", "run",  "service",
      "appimage", "deb",   "rpm",  "apk",  "elf",  "so",   "dll",
  };
  for (std::string_view denied : kDangerous) {
    if (ext == denied) {
      return true;
    }
  }
  return false;
}

std::string encode_file_payload(const std::vector<uint8_t>& raw,
                                std::string_view ext) {
  if (ext.empty() || ext.size() > kMaxExtensionLength) {
    throw Error("internal: invalid extension in encode_file_payload");
  }
  if (raw.empty()) {
    throw Error("internal: empty file in encode_file_payload");
  }

  std::string payload;
  payload.reserve(1 + 4 + ext.size() + raw.size());

  // Type byte
  payload.push_back(static_cast<char>(kPayloadTypeFile));
  // Extension length (u32 LE)
  put_u32_le(payload, static_cast<uint32_t>(ext.size()));
  // Extension characters
  payload.append(ext.data(), ext.size());
  // Raw file bytes
  payload.append(reinterpret_cast<const char*>(raw.data()), raw.size());

  return payload;
}

std::optional<FilePayload> decode_file_payload(const std::string& plaintext) {
  if (plaintext.empty() ||
      static_cast<uint8_t>(plaintext[0]) != kPayloadTypeFile) {
    return std::nullopt;
  }

  // Minimum: type(1) + ext_len(4) + ext(≥1) + data(≥1) = 7 bytes
  const auto* p = reinterpret_cast<const unsigned char*>(plaintext.data());
  const std::size_t total = plaintext.size();

  if (total < 7) {
    throw Error("file payload is too short to be valid");
  }

  const uint32_t ext_len = get_u32_le(p + 1);
  if (ext_len == 0 || ext_len > kMaxExtensionLength) {
    throw Error("file payload has an invalid extension length");
  }
  if (total < 1u + 4u + ext_len + 1u) {
    throw Error("file payload is truncated (extension or body missing)");
  }

  FilePayload out;
  // Sanitise the sender's extension before it is ever used in a file name.
  out.ext = sanitized_extension(
      std::string_view(reinterpret_cast<const char*>(p + 5), ext_len));
  if (out.ext.empty()) {
    out.ext = "bin";
  }
  const std::size_t body_start = 5 + ext_len;
  out.bytes.assign(p + body_start, p + total);
  return out;
}

std::string stage_file(const FilePayload& file) {
  // A type the desktop may execute is never staged at all: the dispatch keys
  // off the extension, so a verified-but-hostile sender could otherwise have
  // the receiver run a ".desktop" or a shell script from the folder.
  if (is_dangerous_extension(file.ext)) {
    throw Error("refusing to open a '." + file.ext +
                "' file: that type can run code, so it is not opened "
                "automatically; save it and inspect it yourself");
  }

  const std::string& dir = staging_directory();
  if (dir.empty()) {
    throw Error("cannot create a private folder to stage the file in");
  }

  // ── step 1: stage the file at a real path ───────────────────────────────
  std::string path = dir + "/ratchet-file-XXXXXX." + file.ext;
  const int suffix_len = static_cast<int>(1 + file.ext.size());
  std::vector<char> tmpl(path.begin(), path.end());
  tmpl.push_back('\0');

  // O_CLOEXEC: the desktop opens the path itself and has no business holding
  // this descriptor. mkostemps creates the file 0600; fchmod makes that
  // independent of the umask.
  const int file_fd = ::mkostemps(tmpl.data(), suffix_len, O_CLOEXEC);
  if (file_fd < 0) {
    throw Error(std::string("cannot create temporary file: ") +
                std::strerror(errno));
  }
  path.assign(tmpl.data());  // mkostemps filled in the X's
  (void)::fchmod(file_fd, 0600);

  // ── step 2: write file bytes ────────────────────────────────────────────
  if (!write_all(file_fd, file.bytes.data(), file.bytes.size())) {
    const std::string msg = std::strerror(errno);
    ::close(file_fd);
    (void)::unlink(path.c_str());
    throw Error("cannot write file to temporary file: " + msg);
  }
  ::close(file_fd);
  return path;
}

void open_in_file_manager(const FilePayload& file) {
  // The file is not handed to an application directly. The bytes are staged at
  // a real path on a private tmpfs -- a sandboxed application reached through
  // xdg-desktop-portal does not inherit our descriptors, so a memfd or
  // /proc/self/fd path cannot be used -- and the *folder* holding it is opened
  // in the file manager, so the receiver chooses what to do with it. The folder
  // is removed when ratchet-usb exits.
  const std::string path = stage_file(file);
  const std::string dir = std::filesystem::path(path).parent_path().string();

  // ── step 3: fork + exec xdg-open on the folder ───────────────────────────
  const pid_t pid = ::fork();
  if (pid < 0) {
    const std::string msg = std::strerror(errno);
    (void)::unlink(path.c_str());
    throw Error("cannot fork for the file manager: " + msg);
  }

  if (pid == 0) {
    // ── child ──────────────────────────────────────────────────────────────
    // Detach from the process group so the file manager does not receive
    // terminal signals aimed at ratchet-usb, then hand it the folder.
    (void)::setsid();
    ::execlp("xdg-open", "xdg-open", dir.c_str(), nullptr);
    _exit(127);  // exec only returns on failure
  }

  // ── step 4: wait for xdg-open, which returns once the folder is handed over
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }

  // Report failure only when xdg-open could not be found at all (exit 127).
  if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
    throw Error(
        "the file could not be opened (xdg-open not found); "
        "install xdg-utils or open it manually");
  }
}

}  // namespace ratchet::file
