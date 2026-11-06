#include <string>

#include "ratchet/ephemeral.hpp"
#include "ratchet/file.hpp"
#include "ratchet/message.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

// A one-byte body keeps the framing tests independent of any padding bucket.
const std::string kBody = "x";

}  // namespace

TEST("ephemeral: ordinary text is not ephemeral") {
  CHECK(!ephemeral::decode("hello").has_value());
  CHECK(!ephemeral::decode("").has_value());
  // 0x02 is the file marker, not ours: leave it to the file layer.
  CHECK(!ephemeral::decode(std::string("\x02"
                                       "rest",
                                       5))
             .has_value());
}

TEST("ephemeral: encode/decode round-trips every TTL and burn combination") {
  const ephemeral::Ttl ttls[] = {ephemeral::Ttl::OneHour, ephemeral::Ttl::OneDay,
                                 ephemeral::Ttl::SevenDays};
  for (const ephemeral::Ttl ttl : ttls) {
    for (const bool burn : {false, true}) {
      const ephemeral::Expiry expiry{ttl, burn};
      const std::string wrapped = ephemeral::encode(kBody, expiry);
      // Four header bytes, all inside the existing plaintext limit.
      CHECK_EQ(wrapped.size(), kBody.size() + 4u);
      const std::optional<ephemeral::Decoded> decoded =
          ephemeral::decode(wrapped);
      CHECK(decoded.has_value());
      CHECK(decoded->expiry.ttl == ttl);
      CHECK_EQ(decoded->expiry.burn_after_reading, burn);
      CHECK_EQ(decoded->body, kBody);
    }
  }
}

TEST("ephemeral: burn without a TTL round-trips") {
  const std::string wrapped =
      ephemeral::encode(kBody, {ephemeral::Ttl::None, true});
  const std::optional<ephemeral::Decoded> decoded =
      ephemeral::decode(wrapped);
  CHECK(decoded.has_value());
  CHECK(decoded->expiry.ttl == ephemeral::Ttl::None);
  CHECK(decoded->expiry.burn_after_reading);
  CHECK_EQ(decoded->body, kBody);
}

TEST("ephemeral: wrapping a file payload nests cleanly") {
  const std::vector<uint8_t> raw = {0x01, 0x02, 0x03};
  const std::string framed = file::encode_file_payload(raw, "bin");
  const std::string wrapped =
      ephemeral::encode(framed, {ephemeral::Ttl::OneDay, false});
  const std::optional<ephemeral::Decoded> decoded =
      ephemeral::decode(wrapped);
  CHECK(decoded.has_value());
  const std::optional<file::FilePayload> file =
      file::decode_file_payload(decoded->body);
  CHECK(file.has_value());
  CHECK_EQ(file->ext, std::string("bin"));
  CHECK(file->bytes == raw);
}

TEST("ephemeral: a non-ephemeral expiry is refused at encode time") {
  CHECK_THROWS(
      ephemeral::encode(kBody, {ephemeral::Ttl::None, false}));
  CHECK_THROWS(ephemeral::encode("", {ephemeral::Ttl::OneHour, false}));
}

TEST("ephemeral: a truncated or versioned header is rejected, not shown") {
  // Marker alone, and marker plus a partial header.
  CHECK_THROWS(ephemeral::decode(std::string("\x03", 1)));
  CHECK_THROWS(ephemeral::decode(std::string("\x03\x01\x01", 3)));
  CHECK_THROWS(ephemeral::decode(std::string("\x03\x01\x01\x00", 4)));
  // Future version.
  CHECK_THROWS(ephemeral::decode(std::string("\x03\x02\x01\x00"
                                             "x",
                                             5)));
  // Unknown TTL.
  CHECK_THROWS(ephemeral::decode(std::string("\x03\x01\x09\x00"
                                             "x",
                                             5)));
  // Reserved flag bits must be zero so a future flag is never ignored.
  CHECK_THROWS(ephemeral::decode(std::string("\x03\x01\x01\x02"
                                             "x",
                                             5)));
  // A header that names no expiry at all is not an ordinary message.
  CHECK_THROWS(ephemeral::decode(std::string("\x03\x01\x00\x00"
                                             "x",
                                             5)));
}

TEST("ephemeral: TTL helpers agree with each other") {
  CHECK_EQ(ephemeral::ttl_seconds(ephemeral::Ttl::None), 0u);
  CHECK_EQ(ephemeral::ttl_seconds(ephemeral::Ttl::OneHour), 3600u);
  CHECK_EQ(ephemeral::ttl_seconds(ephemeral::Ttl::OneDay), 86400u);
  CHECK_EQ(ephemeral::ttl_seconds(ephemeral::Ttl::SevenDays), 604800u);
  CHECK_EQ(std::string(ephemeral::ttl_label(ephemeral::Ttl::OneHour)),
           std::string("1h"));

  ephemeral::Ttl ttl = ephemeral::Ttl::None;
  CHECK(ephemeral::parse_ttl("1h", ttl));
  CHECK(ttl == ephemeral::Ttl::OneHour);
  CHECK(ephemeral::parse_ttl("24h", ttl));
  CHECK(ttl == ephemeral::Ttl::OneDay);
  CHECK(ephemeral::parse_ttl("7d", ttl));
  CHECK(ttl == ephemeral::Ttl::SevenDays);
  CHECK(ephemeral::parse_ttl("off", ttl));
  CHECK(ttl == ephemeral::Ttl::None);
  CHECK(!ephemeral::parse_ttl("60m", ttl));
  CHECK(!ephemeral::parse_ttl("1H", ttl));
  CHECK(!ephemeral::parse_ttl("", ttl));
  CHECK(!ephemeral::is_ephemeral({ephemeral::Ttl::None, false}));
  CHECK(ephemeral::is_ephemeral({ephemeral::Ttl::None, true}));
  CHECK(ephemeral::is_ephemeral({ephemeral::Ttl::OneHour, false}));
}

TEST("ephemeral: an oversized body is refused before encrypting") {
  const std::string big(message::kMaxPlaintextBytes - 4, 'a');
  const std::string wrapped =
      ephemeral::encode(big, {ephemeral::Ttl::OneHour, false});
  CHECK_EQ(wrapped.size(), message::kMaxPlaintextBytes);
  // Four header bytes push a 4 MiB body over the limit: the sender must see
  // the same ceiling the ratchet enforces, not a ciphertext that cannot exist.
  CHECK_THROWS(ephemeral::encode(
      std::string(message::kMaxPlaintextBytes - 2, 'a'),
      {ephemeral::Ttl::OneHour, false}));
}
