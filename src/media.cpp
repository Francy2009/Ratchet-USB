#include "ratchet/media.hpp"

#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <sstream>

#include "ratchet/vault.hpp"

namespace fs = std::filesystem;

namespace ratchet::media {
namespace {

// /proc/mounts escapes characters that would otherwise break the field layout.
std::string unescape_octal(std::string_view field) {
  std::string out;
  out.reserve(field.size());
  for (std::size_t i = 0; i < field.size(); ++i) {
    const bool has_triple = i + 3 < field.size();
    if (field[i] == '\\' && has_triple && field[i + 1] >= '0' &&
        field[i + 1] <= '7' && field[i + 2] >= '0' && field[i + 2] <= '7' &&
        field[i + 3] >= '0' && field[i + 3] <= '7') {
      const int value = (field[i + 1] - '0') * 64 + (field[i + 2] - '0') * 8 +
                        (field[i + 3] - '0');
      out.push_back(static_cast<char>(value));
      i += 3;
    } else {
      out.push_back(field[i]);
    }
  }
  return out;
}

std::string read_first_line(const fs::path& path) {
  std::ifstream in(path);
  if (!in) {
    return {};
  }
  std::string line;
  std::getline(in, line);
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r' ||
                           line.back() == ' ')) {
    line.pop_back();
  }
  return line;
}

std::string read_file_text(const fs::path& path) {
  std::ifstream in(path);
  if (!in) {
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

}  // namespace

std::vector<Mount> parse_mounts(std::string_view text) {
  std::vector<Mount> mounts;
  std::size_t pos = 0;

  while (pos <= text.size()) {
    const std::size_t nl = text.find('\n', pos);
    const std::string_view line =
        text.substr(pos, (nl == std::string_view::npos ? text.size() : nl) - pos);
    if (nl == std::string_view::npos) {
      pos = text.size() + 1;
    } else {
      pos = nl + 1;
    }
    if (line.empty()) {
      continue;
    }

    // "<device> <mount point> <type> <options> <dump> <pass>"
    const std::size_t sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) {
      continue;
    }
    const std::size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) {
      continue;
    }

    const std::string_view device = line.substr(0, sp1);
    // Only real block devices: everything else is a pseudo filesystem that
    // could never be a USB stick.
    if (!device.starts_with("/dev/")) {
      continue;
    }

    Mount mount;
    mount.device = std::string(device);
    mount.mount_point = fs::path(unescape_octal(line.substr(sp1 + 1, sp2 - sp1 - 1)));
    mounts.push_back(std::move(mount));
  }

  return mounts;
}

bool device_is_removable(const std::string& device, const fs::path& sys_root) {
  const std::string name = fs::path(device).filename().string();
  if (name.empty()) {
    return false;
  }

  const fs::path link = sys_root / "class" / "block" / name;
  std::error_code ec;
  fs::path resolved = fs::canonical(link, ec);
  if (ec) {
    return false;
  }

  // A USB stick usually appears as a partition, whose sysfs directory sits
  // inside the disk's; the "removable" flag lives on the disk. Check the
  // partition's own directory first so a whole-disk device works too.
  for (const fs::path& candidate : {resolved, resolved.parent_path()}) {
    const fs::path flag = candidate / "removable";
    if (fs::exists(flag, ec)) {
      if (read_first_line(flag) == "1") {
        return true;
      }
      break;
    }
  }

  // Sticks that report removable=0 are still removable if they hang off USB.
  const std::string path_text = resolved.string();
  return path_text.find("/usb") != std::string::npos;
}

std::vector<fs::path> removable_drives() {
  const std::string mounts_text = read_file_text("/proc/mounts");
  if (mounts_text.empty()) {
    return {};
  }

  std::vector<fs::path> drives;
  for (const Mount& mount : parse_mounts(mounts_text)) {
    // "/" is never offered, whatever the kernel says about the device: writing
    // the vault to the running system's root is the one outcome this tool
    // exists to avoid.
    if (mount.mount_point == "/") {
      continue;
    }
    std::error_code ec;
    if (!fs::is_directory(mount.mount_point, ec)) {
      continue;
    }
    if (::access(mount.mount_point.c_str(), W_OK | X_OK) != 0) {
      continue;
    }
    if (!device_is_removable(mount.device)) {
      continue;
    }
    if (std::find(drives.begin(), drives.end(), mount.mount_point) ==
        drives.end()) {
      drives.push_back(mount.mount_point);
    }
  }
  return drives;
}

std::vector<fs::path> drives_with_vault() {
  std::vector<fs::path> found;
  for (const fs::path& drive : removable_drives()) {
    std::error_code ec;
    if (fs::exists(vault::vault_path(drive), ec)) {
      found.push_back(drive);
    }
  }
  return found;
}

}  // namespace ratchet::media
