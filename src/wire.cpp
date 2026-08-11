#include "ratchet/wire.hpp"

#include <sodium.h>

#include <cctype>
#include <cstring>

#include "ratchet/secure.hpp"

namespace ratchet::wire {
namespace {

std::string strip_whitespace(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    if (std::isspace(static_cast<unsigned char>(c)) == 0) {
      out.push_back(c);
    }
  }
  return out;
}

}  // namespace

std::string encode_block(std::string_view label, const uint8_t* data,
                         std::size_t len) {
  init_sodium();

  std::string b64(sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL),
                  '\0');
  sodium_bin2base64(b64.data(), b64.size(), data, len,
                    sodium_base64_VARIANT_ORIGINAL);
  // sodium_bin2base64 writes a trailing NUL that sodium_base64_encoded_len
  // already counted; drop it from the string's logical length.
  b64.resize(std::strlen(b64.c_str()));

  std::string out;
  out += "-----BEGIN RATCHET ";
  out += label;
  out += "-----\n";
  for (std::size_t i = 0; i < b64.size(); i += 64) {
    out += b64.substr(i, 64);
    out += '\n';
  }
  out += "-----END RATCHET ";
  out += label;
  out += "-----\n";
  return out;
}

std::vector<uint8_t> decode_block(std::string_view expected_label,
                                  std::string_view text) {
  init_sodium();

  const std::string begin_marker =
      "-----BEGIN RATCHET " + std::string(expected_label) + "-----";
  const std::string end_marker =
      "-----END RATCHET " + std::string(expected_label) + "-----";

  const std::size_t begin_pos = text.find(begin_marker);
  if (begin_pos == std::string_view::npos) {
    throw Error("expected a '" + std::string(expected_label) +
               "' block (BEGIN marker not found)");
  }
  const std::size_t payload_start = begin_pos + begin_marker.size();
  const std::size_t end_pos = text.find(end_marker, payload_start);
  if (end_pos == std::string_view::npos) {
    throw Error("truncated block: END marker not found");
  }

  const std::string b64 =
      strip_whitespace(text.substr(payload_start, end_pos - payload_start));

  std::vector<uint8_t> out(b64.size());  // upper bound
  std::size_t out_len = 0;
  if (sodium_base642bin(out.data(), out.size(), b64.data(), b64.size(),
                        nullptr, &out_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
    throw Error("invalid base64 in block");
  }
  out.resize(out_len);
  return out;
}

}  // namespace ratchet::wire
