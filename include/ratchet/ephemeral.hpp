// ephemeral.hpp — sender-chosen expiry for Ratchet-USB messages.
//
// An ephemeral message is an ordinary 1:1 or group plaintext with a small
// header prepended *inside* the AEAD-encrypted framing, next to the file
// marker file.hpp already defines:
//
//   Ephemeral payload:
//     [0x03]  one byte — kPayloadTypeEphemeral marker
//     [0x01]  one byte — kEphemeralVersion
//     [ttl]   one byte — 0 = none (burn only), 1 = 1h, 2 = 24h, 3 = 7d
//     [flags] one byte — bit 0 = burn after reading, other bits must be zero
//     [body]  remaining bytes — the text, or the already-framed file payload
//
// Why it rides inside the plaintext rather than in the envelope: everything
// outside the AEAD is cleartext metadata. A per-message TTL out there would
// be a fingerprint (this message expires, that one does not) visible to
// anyone holding the block, and it would not be authenticated — anyone could
// rewrite it. Inside, it is covered by the same tag as the body and adds no
// observable wire difference beyond the few bytes of header, which the
// bucketed padding already absorbs for short messages.
//
// Why fixed buckets and not a free-form duration: a free-form timestamp is
// both a fingerprint (every sender picks a different second) and a clock to
// argue with. The buckets (1h/24h/7d) plus burn-after-reading are coarse
// enough to carry no sender identity, and the receiver enforces them against
// its own monotonic clock — never against a timestamp the sender chose, which
// would let a hostile or simply wrong sender clock dictate expiry.
//
// What this module does and does not promise: it only frames and parses. It
// does not keep time, does not store anything, and does not delete anything —
// the vault keeps no message history, so there is nothing to delete. Expiry
// means the receiver refuses display and wipes UI state and staged files, and
// that enforcement is receiver-side and best-effort: it stops later exposure,
// not screenshots, copies, or a modified client. A TTL is a policy hint from
// the sender, not a revocation.
//
// Compatibility: a plaintext whose first byte is not 0x03 is ordinary text (or
// a file payload) and decodes to nullopt, so every message sent before this
// existed keeps working. The reverse is not true and cannot be: an old client
// that receives an ephemeral message sees the 0x03 header bytes as text. That
// is why only explicitly ephemeral messages are wrapped, and why the header
// is deliberately tiny and self-describing rather than a new envelope
// version.
//
// 0x03 is ETX: like the 0x02 STX file marker, it never begins user-typed text,
// so the two cases are unambiguous for anything typed or pasted in the
// interfaces. A raw stdin payload that happens to begin with 0x03 is treated
// as an ephemeral header and rejected unless it parses — the same rule the
// file framing already applies to 0x02.

#ifndef RATCHET_EPHEMERAL_HPP
#define RATCHET_EPHEMERAL_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ratchet::ephemeral {

// Type byte at offset 0 of every ephemeral payload. ETX, chosen for the same
// reason file.hpp chose STX: no typed message begins with it.
inline constexpr uint8_t kPayloadTypeEphemeral = 0x03u;

// The only header version this build writes and reads. A future version must
// be rejected, not skipped: the bytes after the version are version-defined.
inline constexpr uint8_t kEphemeralVersion = 0x01u;

// Burn flag bit inside the flags byte. All other bits are reserved and must
// be zero on the wire, so a future flag cannot be silently ignored.
inline constexpr uint8_t kBurnFlag = 0x01u;

// Sender-chosen lifetime, as fixed buckets. None means "no time limit" and is
// only valid together with burn-after-reading: without either, the message is
// not ephemeral and must be sent unwrapped.
enum class Ttl : uint8_t {
  None = 0,
  OneHour = 1,
  OneDay = 2,
  SevenDays = 3,
};

struct Expiry {
  Ttl ttl = Ttl::None;
  bool burn_after_reading = false;
};

// Seconds for each bucket, for the receiver's monotonic deadline
// (received_monotonic + ttl_seconds). None yields 0.
uint64_t ttl_seconds(Ttl ttl);

// Short label for display and --ttl parsing: "off", "1h", "24h", "7d".
// Returns "?" for a value outside the enum, which can only come from a
// corrupted or future header that decode() already rejected.
const char* ttl_label(Ttl ttl);

// Parses "off", "1h", "24h" or "7d" (exact match, lowercase). Returns false
// for anything else, so the CLI can reject a typo before encrypting.
bool parse_ttl(std::string_view text, Ttl& out);

// True when this expiry asks for anything at all: a time limit, burning, or
// both. encode() refuses anything else, so a plain message can never gain a
// header by accident.
bool is_ephemeral(Expiry expiry);

// Wraps `inner` (plain text, or the already-framed file payload) with the
// 4-byte header. Throws Error when the expiry is not ephemeral, when `inner`
// is empty, or when header + inner would exceed the plaintext limit.
std::string encode(const std::string& inner, Expiry expiry);

struct Decoded {
  Expiry expiry{};
  std::string body;  // the inner text or file payload, without the header
};

// Unwraps an ephemeral payload. Returns nullopt for ordinary input (empty or
// first byte != 0x03), which the caller handles as text-or-file exactly as
// before. Throws Error when the header is present but malformed: bad version,
// unknown TTL, reserved flag bits, a non-ephemeral (None + no burn) header, or
// an empty body. A malformed header is refused rather than shown as text,
// because displaying it would leak the header bytes as if they were content
// and silently drop the sender's expiry intent.
std::optional<Decoded> decode(const std::string& plaintext);

}  // namespace ratchet::ephemeral

#endif  // RATCHET_EPHEMERAL_HPP
