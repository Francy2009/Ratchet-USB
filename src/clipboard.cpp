// clipboard.cpp — see include/ratchet/clipboard.hpp for why this exists and
// why it does not use OSC 52.

#include "ratchet/clipboard.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/secure.hpp"

namespace ratchet::clipboard {
namespace {

struct Backend {
  const char* name;
  // argv including argv[0]; each list ends with a null pointer. Every backend
  // takes at most four arguments, so execlp below has room for them all.
  const char* args[6];
};

const std::vector<Backend>& backends() {
  static const std::vector<Backend> table = {
      {"wl-copy", {"wl-copy", nullptr}},
      {"xclip", {"xclip", "-selection", "clipboard", "-in", nullptr}},
      {"xsel", {"xsel", "--clipboard", "--input", nullptr}},
  };
  return table;
}

bool is_executable_file(const std::string& path) {
  if (::access(path.c_str(), X_OK) != 0) {
    return false;
  }
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool on_path(const char* name) {
  const char* path = std::getenv("PATH");
  if (path == nullptr) {
    return false;
  }
  const std::string_view all(path);
  std::size_t pos = 0;
  while (pos <= all.size()) {
    const std::size_t colon = all.find(':', pos);
    const std::size_t end = colon == std::string_view::npos ? all.size() : colon;
    std::string dir(all.substr(pos, end - pos));
    if (dir.empty()) {
      dir = ".";
    }
    if (is_executable_file(dir + "/" + name)) {
      return true;
    }
    if (colon == std::string_view::npos) {
      break;
    }
    pos = colon + 1;
  }
  return false;
}

// Forks `backend`, feeds it `text` on stdin, and returns true only when it
// exits zero. A child that could not exec (127) is reported as failure so the
// caller moves on to the next backend.
bool run_backend(const Backend& backend, std::string_view text) {
  int fds[2];
  if (::pipe(fds) != 0) {
    return false;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(fds[0]);
    ::close(fds[1]);
    return false;
  }

  if (pid == 0) {
    ::close(fds[1]);
    if (::dup2(fds[0], STDIN_FILENO) < 0) {
      _exit(127);
    }
    ::close(fds[0]);
    ::execlp(backend.name, backend.args[0], backend.args[1], backend.args[2],
             backend.args[3], backend.args[4], nullptr);
    _exit(127);
  }

  ::close(fds[0]);
  const char* cursor = text.data();
  std::size_t left = text.size();
  while (left > 0) {
    const ssize_t written = ::write(fds[1], cursor, left);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;  // a backend that closed early; the wait below reports it
    }
    cursor += written;
    left -= static_cast<std::size_t>(written);
  }
  ::close(fds[1]);

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// The commands that read the clipboard, in the order they are tried.
const std::vector<Backend>& read_backends() {
  static const std::vector<Backend> table = {
      {"wl-paste", {"wl-paste", "-n", nullptr}},
      {"xclip", {"xclip", "-selection", "clipboard", "-o", nullptr}},
      {"xsel", {"xsel", "--clipboard", "--output", nullptr}},
  };
  return table;
}

// Runs `backend` and returns what it writes to standard output. `ok` is false
// when the command could not be started or exited non-zero, so the caller can
// move on; content over kMaxPasteBytes throws instead of being silently cut.
struct ReadResult {
  bool ok = false;
  std::string out;
};

ReadResult run_read_backend(const Backend& backend) {
  int fds[2];
  if (::pipe(fds) != 0) {
    return {};
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(fds[0]);
    ::close(fds[1]);
    return {};
  }
  if (pid == 0) {
    ::close(fds[0]);
    if (::dup2(fds[1], STDOUT_FILENO) < 0) {
      _exit(127);
    }
    ::close(fds[1]);
    ::execlp(backend.name, backend.args[0], backend.args[1], backend.args[2],
             backend.args[3], backend.args[4], nullptr);
    _exit(127);
  }

  ::close(fds[1]);
  ReadResult result;
  char buffer[8192];
  for (;;) {
    const ssize_t n = ::read(fds[0], buffer, sizeof buffer);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (n == 0) {
      break;
    }
    if (result.out.size() + static_cast<std::size_t>(n) > kMaxPasteBytes) {
      ::close(fds[0]);
      ::kill(pid, SIGKILL);
      (void)::waitpid(pid, nullptr, 0);
      throw Error("clipboard content is too large to paste");
    }
    result.out.append(buffer, static_cast<std::size_t>(n));
  }
  ::close(fds[0]);

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  result.ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  return result;
}

}  // namespace

void copy(std::string_view text) {
  // A backend that exits before reading everything closes the pipe, and the
  // default SIGPIPE action would kill this process mid-frame. Ignore it for
  // the duration and let the wait status decide success.
  struct sigaction ignore {};
  struct sigaction previous {};
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  ignore.sa_flags = 0;
  ::sigaction(SIGPIPE, &ignore, &previous);

  bool copied = false;
  for (const Backend& backend : backends()) {
    if (!on_path(backend.name)) {
      continue;
    }
    if (run_backend(backend, text)) {
      copied = true;
      break;
    }
  }

  ::sigaction(SIGPIPE, &previous, nullptr);
  if (!copied) {
    throw Error(
        "no clipboard tool found; install wl-clipboard, xclip or xsel");
  }
}

std::string paste() {
  bool available = false;
  for (const Backend& backend : read_backends()) {
    if (!on_path(backend.name)) {
      continue;
    }
    available = true;
    const ReadResult result = run_read_backend(backend);
    if (result.ok) {
      return result.out;
    }
  }
  if (!available) {
    throw Error(
        "no clipboard tool found; install wl-clipboard, xclip or xsel");
  }
  throw Error("could not read the clipboard");
}

}  // namespace ratchet::clipboard
