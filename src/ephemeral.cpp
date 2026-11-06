#include "ratchet/ephemeral.hpp"

#include "ratchet/message.hpp"
#include "ratchet/secure.hpp"

namespace ratchet::ephemeral {

uint64_t ttl_seconds(Ttl ttl) {
  // ULL literals: the products are computed in 64 bits, so no implicit
  // widening of a 32-bit multiplication is left for the caller to wonder about.
  switch (ttl) {
    case Ttl::None:
      return 0;
    case Ttl::OneHour:
      return 60ULL * 60ULL;
    case Ttl::OneDay:
      return 24ULL * 60ULL * 60ULL;
    case Ttl::SevenDays:
      return 7ULL * 24ULL * 60ULL * 60ULL;
  }
  return 0;
}

const char* ttl_label(Ttl ttl) {
  switch (ttl) {
    case Ttl::None:
      return "off";
    case Ttl::OneHour:
      return "1h";
    case Ttl::OneDay:
      return "24h";
    case Ttl::SevenDays:
      return "7d";
  }
  return "?";
}

bool parse_ttl(std::string_view text, Ttl& out) {
  if (text == "off") {
    out = Ttl::None;
    return true;
  }
  if (text == "1h") {
    out = Ttl::OneHour;
    return true;
  }
  if (text == "24h") {
    out = Ttl::OneDay;
    return true;
  }
  if (text == "7d") {
    out = Ttl::SevenDays;
    return true;
  }
  return false;
}

bool is_ephemeral(Expiry expiry) {
  return expiry.ttl != Ttl::None || expiry.burn_after_reading;
}

std::string encode(const std::string& inner, Expiry expiry) {
  if (!is_ephemeral(expiry)) {
    throw Error("internal: ephemeral framing needs a TTL or burn flag");
  }
  if (inner.empty()) {
    throw Error("internal: empty message in ephemeral encode");
  }
  constexpr std::size_t kHeaderBytes = 4;
  if (inner.size() + kHeaderBytes > message::kMaxPlaintextBytes) {
    throw Error("message exceeds the 4 MiB plaintext limit");
  }
  std::string out;
  out.reserve(kHeaderBytes + inner.size());
  out.push_back(static_cast<char>(kPayloadTypeEphemeral));
  out.push_back(static_cast<char>(kEphemeralVersion));
  out.push_back(static_cast<char>(expiry.ttl));
  out.push_back(static_cast<char>(expiry.burn_after_reading ? kBurnFlag : 0x00));
  out.append(inner.data(), inner.size());
  return out;
}

std::optional<Decoded> decode(const std::string& plaintext) {
  if (plaintext.empty() ||
      static_cast<uint8_t>(plaintext[0]) != kPayloadTypeEphemeral) {
    return std::nullopt;
  }
  // Header (4) + at least one body byte. Anything shorter is truncated, not
  // text: returning it as a message would display header bytes as content.
  constexpr std::size_t kMinBytes = 5;
  if (plaintext.size() < kMinBytes) {
    throw Error("ephemeral message is too short to be valid");
  }
  const uint8_t version = static_cast<uint8_t>(plaintext[1]);
  if (version != kEphemeralVersion) {
    throw Error("ephemeral message has an unsupported version");
  }
  const uint8_t ttl_raw = static_cast<uint8_t>(plaintext[2]);
  if (ttl_raw > static_cast<uint8_t>(Ttl::SevenDays)) {
    throw Error("ephemeral message has an invalid TTL");
  }
  const uint8_t flags = static_cast<uint8_t>(plaintext[3]);
  if ((flags & ~kBurnFlag) != 0) {
    throw Error("ephemeral message has invalid flags");
  }
  Expiry expiry;
  expiry.ttl = static_cast<Ttl>(ttl_raw);
  expiry.burn_after_reading = (flags & kBurnFlag) != 0;
  if (!is_ephemeral(expiry)) {
    throw Error("ephemeral message names no expiry");
  }
  Decoded decoded;
  decoded.expiry = expiry;
  decoded.body.assign(plaintext.data() + 4, plaintext.size() - 4);
  return decoded;
}

}  // namespace ratchet::ephemeral
