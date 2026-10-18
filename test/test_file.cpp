#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/file.hpp"
#include "ratchet/message.hpp"
#include "test_support.hpp"

using namespace ratchet;
namespace fs = std::filesystem;

namespace {

// A throwaway file under the system temporary directory. load_file refuses a
// path it does not own, so the tests create the files themselves.
class TempFile {
 public:
  explicit TempFile(std::string suffix = "") {
    path_ = fs::temp_directory_path() /
            ("ratchet_file_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter()++) + suffix);
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

std::vector<uint8_t> text_bytes(std::string_view text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

}  // namespace

// --- extension selection ------------------------------------------------------

TEST("file: an image keeps its real extension whatever the name says") {
  CHECK_EQ(file::extension_for(fs::path("/tmp/photo.dat"), png_bytes()),
           std::string("png"));
  CHECK_EQ(file::extension_for(fs::path("/tmp/photo.dat"), jpeg_bytes()),
           std::string("jpg"));
}

TEST("file: other files take their name's extension, lowercased") {
  const std::vector<uint8_t> body = text_bytes("hello");
  CHECK_EQ(file::extension_for(fs::path("/tmp/Report.PDF"), body),
           std::string("pdf"));
  CHECK_EQ(file::extension_for(fs::path("/tmp/sheet.ODS"), body),
           std::string("ods"));
}

TEST("file: a name with no usable extension becomes bin") {
  const std::vector<uint8_t> body = text_bytes("hello");
  CHECK_EQ(file::extension_for(fs::path("/tmp/README"), body),
           std::string("bin"));
  CHECK_EQ(file::extension_for(fs::path("/tmp/archive."), body),
           std::string("bin"));
}

// --- framing ------------------------------------------------------------------

TEST("file: encode/decode is a round trip") {
  const std::vector<uint8_t> raw = png_bytes(64);
  const std::string payload = file::encode_file_payload(raw, "png");

  const std::optional<file::FilePayload> decoded =
      file::decode_file_payload(payload);
  CHECK(decoded.has_value());
  CHECK_EQ(decoded->ext, std::string("png"));
  CHECK(decoded->bytes == raw);
}

TEST("file: a non-image extension round-trips") {
  const std::vector<uint8_t> raw = text_bytes("a document");
  const std::string payload = file::encode_file_payload(raw, "odt");

  const std::optional<file::FilePayload> decoded =
      file::decode_file_payload(payload);
  CHECK(decoded.has_value());
  CHECK_EQ(decoded->ext, std::string("odt"));
  CHECK(decoded->bytes == raw);
}

TEST("file: ordinary text is not mistaken for a file") {
  CHECK(!file::decode_file_payload("hello").has_value());
  CHECK(!file::decode_file_payload("").has_value());
  // Only a leading 0x02 marks a file.
  CHECK(!file::decode_file_payload("a message").has_value());
}

TEST("file: a hostile extension cannot escape the staging directory") {
  // A sender may put anything in the extension field. decode_file_payload must
  // reduce it to [a-z0-9] before it is ever used in a file name, so an
  // extension such as "../../etc" cannot climb out of the staging directory.
  std::string payload;
  payload.push_back(static_cast<char>(file::kPayloadTypeFile));
  const std::string hostile = "../../etc";
  payload.push_back(static_cast<char>(hostile.size() & 0xFFu));
  payload.push_back('\0');
  payload.push_back('\0');
  payload.push_back('\0');
  payload += hostile;
  payload += "body";

  const std::optional<file::FilePayload> decoded =
      file::decode_file_payload(payload);
  CHECK(decoded.has_value());
  CHECK_EQ(decoded->ext, std::string("etc"));
  CHECK(decoded->bytes == text_bytes("body"));
}

TEST("file: a malformed header is rejected, not read as text") {
  std::string truncated;
  truncated.push_back(static_cast<char>(file::kPayloadTypeFile));
  // Claims a 4-byte extension but carries none.
  truncated.append(3, '\0');
  truncated.push_back('\x04');
  CHECK_THROWS(file::decode_file_payload(truncated));

  // A zero-length extension is invalid.
  std::string zero_ext;
  zero_ext.push_back(static_cast<char>(file::kPayloadTypeFile));
  zero_ext.append(4, '\0');
  zero_ext.push_back('x');
  CHECK_THROWS(file::decode_file_payload(zero_ext));
}

TEST("file: an empty file or extension cannot be encoded") {
  CHECK_THROWS(file::encode_file_payload({}, "png"));
  CHECK_THROWS(file::encode_file_payload(png_bytes(), ""));
}

TEST("file: the framed payload fits inside the message plaintext limit") {
  // The largest accepted file, plus the framing header, must stay under the
  // ratchet's 4 MiB plaintext ceiling or the send would be refused later.
  const std::size_t framed = 1 + 4 + 16 + file::kMaxFileBytes;
  CHECK(framed <= message::kMaxPlaintextBytes);
}

// --- reading from disk --------------------------------------------------------

TEST("file: a valid file is read back byte for byte") {
  TempFile file(".png");
  const std::vector<uint8_t> raw = png_bytes(128);
  file.write(raw);

  const std::vector<uint8_t> loaded = file::load_file(file.path());
  CHECK(loaded == raw);
  CHECK_EQ(file::extension_for(file.path(), loaded), std::string("png"));
}

TEST("file: a non-image file is accepted and keeps its name extension") {
  TempFile file(".odt");
  const std::vector<uint8_t> raw = text_bytes("not an image at all");
  file.write(raw);

  const std::vector<uint8_t> loaded = file::load_file(file.path());
  CHECK(loaded == raw);
  CHECK_EQ(file::extension_for(file.path(), loaded), std::string("odt"));
}

TEST("file: an empty file is refused") {
  TempFile file;
  file.write({});
  CHECK_THROWS(file::load_file(file.path()));
}

TEST("file: a directory is not a regular file") {
  CHECK_THROWS(file::load_file(fs::temp_directory_path()));
}

TEST("file: a file past the size limit is refused") {
  TempFile file;
  std::vector<uint8_t> raw = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
  raw.resize(file::kMaxFileBytes + 1, 0);
  file.write(raw);
  CHECK_THROWS(file::load_file(file.path()));
}
