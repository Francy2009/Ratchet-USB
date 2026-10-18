#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ratchet/message.hpp"
#include "ratchet/photo.hpp"
#include "test_support.hpp"

using namespace ratchet;
namespace fs = std::filesystem;

namespace {

// A throwaway file under the system temporary directory. load_image refuses a
// path it does not own, so the tests create the files themselves.
class TempFile {
 public:
  TempFile() {
    path_ = fs::temp_directory_path() /
            ("ratchet_photo_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter()++));
  }

  ~TempFile() {
    std::error_code ec;
    fs::remove(path_, ec);
  }

  TempFile(const TempFile&) = delete;
  TempFile& operator=(const TempFile&) = delete;

  void write(const std::vector<uint8_t>& bytes) {
    std::ofstream out(path_, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  }

  const fs::path& path() const { return path_; }

 private:
  static int& counter() {
    static int n = 0;
    return n;
  }
  fs::path path_;
};

std::vector<uint8_t> png_bytes(std::size_t body = 16) {
  std::vector<uint8_t> out = {0x89, 0x50, 0x4E, 0x47,
                              0x0D, 0x0A, 0x1A, 0x0A};
  for (std::size_t i = 0; i < body; ++i) {
    out.push_back(static_cast<uint8_t>('a' + (i % 26)));
  }
  return out;
}

std::vector<uint8_t> jpeg_bytes(std::size_t body = 16) {
  std::vector<uint8_t> out = {0xFF, 0xD8, 0xFF, 0xE0};
  for (std::size_t i = 0; i < body; ++i) {
    out.push_back(static_cast<uint8_t>(i & 0xFF));
  }
  return out;
}

}  // namespace

// --- format detection ---------------------------------------------------------

TEST("photo: PNG and JPEG are recognised by their magic bytes") {
  const std::vector<uint8_t> png = png_bytes();
  const std::vector<uint8_t> jpg = jpeg_bytes();
  CHECK_EQ(std::string(photo::extension_for(png)), std::string("png"));
  CHECK_EQ(std::string(photo::extension_for(jpg)), std::string("jpg"));
}

TEST("photo: a payload whose magic bytes are unknown is refused") {
  const std::vector<uint8_t> gif = {'G', 'I', 'F', '8', '9', 'a'};
  CHECK_THROWS(photo::extension_for(gif));
  CHECK_THROWS(photo::extension_for(std::vector<uint8_t>{}));
}

// --- framing ------------------------------------------------------------------

TEST("photo: encode/decode is a round trip") {
  const std::vector<uint8_t> raw = png_bytes(64);
  const std::string payload = photo::encode_photo_payload(raw, "png");

  const std::optional<photo::PhotoPayload> decoded =
      photo::decode_photo_payload(payload);
  CHECK(decoded.has_value());
  CHECK_EQ(decoded->ext, std::string("png"));
  CHECK(decoded->bytes == raw);
}

TEST("photo: ordinary text is not mistaken for an image") {
  CHECK(!photo::decode_photo_payload("hello").has_value());
  CHECK(!photo::decode_photo_payload("").has_value());
  // Only a leading 0x02 marks an image.
  CHECK(!photo::decode_photo_payload("a message").has_value());
}

TEST("photo: a malformed image header is rejected, not read as text") {
  std::string truncated;
  truncated.push_back(static_cast<char>(photo::kPayloadTypeImage));
  // Claims a 4-byte extension but carries none.
  truncated.append(3, '\0');
  truncated.push_back('\x04');
  CHECK_THROWS(photo::decode_photo_payload(truncated));

  // A zero-length extension is invalid.
  std::string zero_ext;
  zero_ext.push_back(static_cast<char>(photo::kPayloadTypeImage));
  zero_ext.append(4, '\0');
  zero_ext.push_back('x');
  CHECK_THROWS(photo::decode_photo_payload(zero_ext));
}

TEST("photo: an empty image or extension cannot be encoded") {
  CHECK_THROWS(photo::encode_photo_payload({}, "png"));
  CHECK_THROWS(photo::encode_photo_payload(png_bytes(), ""));
}

TEST("photo: the framed payload fits inside the message plaintext limit") {
  // The largest accepted image, plus the framing header, must stay under the
  // ratchet's 4 MiB plaintext ceiling or the send would be refused later.
  const std::size_t framed = 1 + 4 + 3 + photo::kMaxImageBytes;
  CHECK(framed <= message::kMaxPlaintextBytes);
}

// --- reading from disk --------------------------------------------------------

TEST("photo: a valid file is read back byte for byte") {
  TempFile file;
  const std::vector<uint8_t> raw = png_bytes(128);
  file.write(raw);

  const std::vector<uint8_t> loaded = photo::load_image(file.path());
  CHECK(loaded == raw);
  CHECK_EQ(std::string(photo::extension_for(loaded)), std::string("png"));
}

TEST("photo: a file that is not an image is refused") {
  TempFile file;
  file.write({'n', 'o', 't', 'a', 'n', 'i', 'm', 'a', 'g', 'e'});
  CHECK_THROWS(photo::load_image(file.path()));
}

TEST("photo: an empty file is refused") {
  TempFile file;
  file.write({});
  CHECK_THROWS(photo::load_image(file.path()));
}

TEST("photo: a directory is not a regular file") {
  CHECK_THROWS(photo::load_image(fs::temp_directory_path()));
}

TEST("photo: an image past the size limit is refused") {
  TempFile file;
  std::vector<uint8_t> raw = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
  raw.resize(photo::kMaxImageBytes + 1, 0);
  file.write(raw);
  CHECK_THROWS(photo::load_image(file.path()));
}
