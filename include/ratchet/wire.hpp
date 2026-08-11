#ifndef RATCHET_WIRE_HPP
#define RATCHET_WIRE_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ratchet::wire {

// Wraps `bytes` as base64 between a "-----BEGIN RATCHET <LABEL>-----" and a
// matching END line, wrapped at 64 columns. This is what gets pasted into the
// actual chat app.
std::string encode_block(std::string_view label, const uint8_t* data,
                         std::size_t len);

// Reverses encode_block. All whitespace inside the block is ignored on
// decode, since copying out of a chat app can reflow or strip line breaks.
// Throws Error if the label does not match (wrong kind of block pasted where
// another was expected) or the payload is not valid base64.
std::vector<uint8_t> decode_block(std::string_view expected_label,
                                  std::string_view text);

}  // namespace ratchet::wire

#endif  // RATCHET_WIRE_HPP
