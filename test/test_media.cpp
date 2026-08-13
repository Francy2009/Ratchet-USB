#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "ratchet/media.hpp"
#include "test_support.hpp"

using namespace ratchet;
namespace fs = std::filesystem;

namespace {

// A throwaway sysfs tree, so the removability check can be exercised without a
// stick plugged in. Laid out the way the kernel does it: /sys/class/block/<part>
// is a symlink into the disk's directory, and "removable" lives on the disk.
class FakeSys {
 public:
  FakeSys() {
    root_ = fs::temp_directory_path() /
            ("ratchet_sys_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter()++));
    fs::create_directories(root_ / "class" / "block");
    fs::create_directories(root_ / "devices");
  }

  ~FakeSys() {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }

  FakeSys(const FakeSys&) = delete;
  FakeSys& operator=(const FakeSys&) = delete;

  // Creates a disk with the given "removable" flag, plus one partition on it.
  void add_disk(const std::string& disk, const std::string& removable,
                const std::string& partition, const std::string& bus = "pci") {
    const fs::path disk_dir =
        root_ / "devices" / bus / ("host-" + disk) / "block" / disk;
    fs::create_directories(disk_dir);
    std::ofstream(disk_dir / "removable") << removable << "\n";

    fs::create_directories(disk_dir / partition);
    fs::create_directory_symlink(disk_dir, root_ / "class" / "block" / disk);
    fs::create_directory_symlink(disk_dir / partition,
                                 root_ / "class" / "block" / partition);
  }

  const fs::path& root() const { return root_; }

 private:
  static int& counter() {
    static int n = 0;
    return n;
  }
  fs::path root_;
};

}  // namespace

// --- parse_mounts ------------------------------------------------------------

TEST("media: parse_mounts keeps only entries backed by a block device") {
  const std::string text =
      "proc /proc proc rw,relatime 0 0\n"
      "sysfs /sys sysfs rw,relatime 0 0\n"
      "/dev/sda2 / ext4 rw,relatime 0 0\n"
      "tmpfs /dev/shm tmpfs rw 0 0\n"
      "/dev/sdb1 /run/media/user/STICK vfat rw,nosuid 0 0\n";
  const std::vector<media::Mount> mounts = media::parse_mounts(text);
  CHECK_EQ(mounts.size(), static_cast<std::size_t>(2));
  CHECK_EQ(mounts[0].device, std::string("/dev/sda2"));
  CHECK_EQ(mounts[0].mount_point.string(), std::string("/"));
  CHECK_EQ(mounts[1].device, std::string("/dev/sdb1"));
  CHECK_EQ(mounts[1].mount_point.string(),
           std::string("/run/media/user/STICK"));
}

// A drive labelled "MY STICK" mounts with the space escaped; taking the field
// verbatim would point at "/run/media/user/MY" and fail to find the vault.
TEST("media: parse_mounts decodes octal escapes in the mount point") {
  const std::string text =
      "/dev/sdb1 /run/media/user/MY\\040STICK vfat rw 0 0\n";
  const std::vector<media::Mount> mounts = media::parse_mounts(text);
  CHECK_EQ(mounts.size(), static_cast<std::size_t>(1));
  CHECK_EQ(mounts[0].mount_point.string(),
           std::string("/run/media/user/MY STICK"));
}

TEST("media: parse_mounts survives junk and a missing trailing newline") {
  CHECK_EQ(media::parse_mounts("").size(), static_cast<std::size_t>(0));
  CHECK_EQ(media::parse_mounts("\n\n").size(), static_cast<std::size_t>(0));
  CHECK_EQ(media::parse_mounts("garbage").size(), static_cast<std::size_t>(0));
  CHECK_EQ(media::parse_mounts("/dev/sdb1").size(),
           static_cast<std::size_t>(0));
  CHECK_EQ(media::parse_mounts("/dev/sdb1 /mnt").size(),
           static_cast<std::size_t>(0));
  // No newline at the end must still yield the entry.
  CHECK_EQ(media::parse_mounts("/dev/sdb1 /mnt vfat rw 0 0").size(),
           static_cast<std::size_t>(1));
}

// --- device_is_removable -----------------------------------------------------

TEST("media: a partition inherits its disk's removable flag") {
  FakeSys sys;
  sys.add_disk("sdb", "1", "sdb1");
  CHECK(media::device_is_removable("/dev/sdb1", sys.root()));
  CHECK(media::device_is_removable("/dev/sdb", sys.root()));
}

TEST("media: a fixed disk is not removable") {
  FakeSys sys;
  sys.add_disk("sda", "0", "sda1");
  CHECK(!media::device_is_removable("/dev/sda1", sys.root()));
  CHECK(!media::device_is_removable("/dev/sda", sys.root()));
}

// Plenty of USB sticks report removable=0; the bus is the giveaway.
TEST("media: a device on the USB bus counts even with removable=0") {
  FakeSys sys;
  sys.add_disk("sdc", "0", "sdc1", "usb");
  CHECK(media::device_is_removable("/dev/sdc1", sys.root()));
}

// NVMe and SD naming (nvme0n1p1, mmcblk0p1) must not be mangled by any
// strip-the-digits shortcut: the disk is found by walking sysfs, not by string
// surgery on the name.
TEST("media: nvme and mmc names resolve to the right disk") {
  FakeSys sys;
  sys.add_disk("nvme0n1", "0", "nvme0n1p1");
  sys.add_disk("mmcblk0", "1", "mmcblk0p1");
  CHECK(!media::device_is_removable("/dev/nvme0n1p1", sys.root()));
  CHECK(media::device_is_removable("/dev/mmcblk0p1", sys.root()));
}

TEST("media: an unknown device is not removable") {
  FakeSys sys;
  CHECK(!media::device_is_removable("/dev/nope", sys.root()));
  CHECK(!media::device_is_removable("", sys.root()));
  CHECK(!media::device_is_removable("/dev/", sys.root()));
}

// --- the real machine --------------------------------------------------------

// Whatever this host looks like, discovery must not offer the running system's
// root, and must not throw when nothing is plugged in.
TEST("media: discovery never offers / and never throws") {
  const std::vector<fs::path> drives = media::removable_drives();
  for (const fs::path& drive : drives) {
    CHECK(drive != fs::path("/"));
  }
  const std::vector<fs::path> with_vault = media::drives_with_vault();
  CHECK(with_vault.size() <= drives.size());
}
