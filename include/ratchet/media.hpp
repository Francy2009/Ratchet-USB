#ifndef RATCHET_MEDIA_HPP
#define RATCHET_MEDIA_HPP

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

// Finding the removable drive on its own, so the common case needs no
// --usb-path at all.
//
// Everything here is best-effort by nature: a mount layout cannot be told apart
// from a removable one with certainty, which is why nothing in this header ever
// decides on its own to write. It offers candidates; the caller confirms with
// the user. The split also keeps the guessing honest -- parse_mounts and
// device_is_removable are pure enough to test, rather than being verifiable
// only by plugging a stick in.
namespace ratchet::media {

struct Mount {
  std::string device;                 // e.g. "/dev/sdb1"
  std::filesystem::path mount_point;  // e.g. "/run/media/user/KINGSTON"
};

// Parses the contents of /proc/mounts. Octal escapes (\040 for a space, and
// friends) are decoded, since a drive label with a space in it is common.
// Pseudo filesystems are dropped: only entries backed by a /dev node are kept.
std::vector<Mount> parse_mounts(std::string_view text);

// Whether the disk backing `device` reports itself as removable, or sits on a
// USB bus (plenty of sticks report removable=0 but hang off USB). `sys_root`
// is a parameter so a test can point it at a fixture instead of the real /sys.
bool device_is_removable(const std::string& device,
                         const std::filesystem::path& sys_root = "/sys");

// Mounted removable drives that are writable directories. Empty when nothing
// is plugged in, or when the platform does not lay its mounts out the way this
// expects -- never an error, since the caller always has --usb-path to fall
// back on.
std::vector<std::filesystem::path> removable_drives();

// Those of `removable_drives()` that already hold a vault.bin.
std::vector<std::filesystem::path> drives_with_vault();

}  // namespace ratchet::media

#endif  // RATCHET_MEDIA_HPP
