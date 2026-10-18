// photo.hpp — encrypted image support for Ratchet-USB.
//
// Images travel through exactly the same Double/Triple Ratchet pipeline as
// text messages. The only thing this module adds is a thin framing layer
// (a single type-byte prefix) that lets the receiver distinguish an image
// payload from a text payload before presenting the appropriate UI.
//
// Wire contract
// ─────────────
// The `plaintext` that session::send() encrypts is one of:
//
//   Text payload  (existing, unchanged):
//     arbitrary bytes  — any message where byte[0] != kPayloadTypeImage
//
//   Image payload (new):
//     [0x02]  one byte — kPayloadTypeImage marker
//     [u32le] four bytes — length of the extension string (e.g. 3 for "jpg")
//     [bytes] extension characters, no NUL
//     [bytes] raw image bytes to end of string
//
// 0x02 is STX (Start of Text) in ASCII and will never appear as the first
// character of a user-typed message, so the two cases are unambiguous.
//
// Nothing in this header touches the ratchet state, the vault or the disk.
// open_photo_in_viewer() is the only function with OS side-effects.

#ifndef RATCHET_PHOTO_HPP
#define RATCHET_PHOTO_HPP

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ratchet::photo {

// Maximum raw image size accepted by load_image().
// Must stay well below message::kMaxPlaintextBytes (4 MiB) once the
// framing header is added (5 + ext_len bytes).
inline constexpr std::size_t kMaxImageBytes =
    std::size_t{4} * 1024u * 1024u - 64u;

// Type-byte placed at offset 0 of every image payload.
inline constexpr uint8_t kPayloadTypeImage = 0x02u;

// Holds a decoded image ready to be shown or written to a viewer.
// The bytes are the raw image (JPEG or PNG); ext is the lowercase extension
// without the leading dot ("jpg" or "png").
struct PhotoPayload {
  std::string            ext;    // "jpg" or "png"
  std::vector<uint8_t>   bytes;  // raw image bytes
};

// Reads an image file from the host filesystem.
//
// Validates:
//  – the path points to a regular file owned by the current user
//  – magic bytes identify it as JPEG (FF D8 FF) or PNG (89 50 4E 47 0D 0A 1A 0A)
//  – the file size does not exceed kMaxImageBytes
//
// Returns the raw bytes on success; throws ratchet::Error on any failure.
// The read is done without any permanent write to the USB drive or host disk.
std::vector<uint8_t> load_image(const std::filesystem::path& path);

// Infers the lowercase extension ("jpg" or "png") from the magic bytes of
// `raw`. Throws Error if the format is not recognised.
std::string_view extension_for(const std::vector<uint8_t>& raw);

// Packs raw image bytes and their extension into the payload format that
// session::send() will encrypt:
//   [0x02][u32-LE ext_len][ext bytes][image bytes]
//
// The returned string becomes the `plaintext` argument for session::send().
// No copy of the image data is left behind by this function.
std::string encode_photo_payload(const std::vector<uint8_t>& raw,
                                 std::string_view ext);

// Returns a PhotoPayload if `plaintext[0] == kPayloadTypeImage`.
// Returns nullopt for ordinary text messages (byte[0] != 0x02).
// Throws Error if the header is present but the payload is structurally
// invalid (truncated length field, oversized extension, empty body, etc.).
std::optional<PhotoPayload> decode_photo_payload(const std::string& plaintext);

// Opens `photo` in the system's default image viewer without writing the
// image to durable storage.
//
// Implementation (Linux):
//  1. Creates a 0600 file with the correct extension under $XDG_RUNTIME_DIR
//     (a tmpfs cleared at logout), or /tmp when that is unavailable.
//  2. Writes the image bytes into it.
//  3. Forks a child that detaches and exec()s "xdg-open <real path>".
//  4. The parent waits for xdg-open, which only asks the desktop to open the
//     path and exits quickly.
//  5. A detached helper unlinks the staged file after a short grace period.
//
// The path passed to xdg-open is a real filesystem path: the viewer is usually
// started as a separate (often sandboxed) process that does not inherit this
// process's file descriptors, so a memfd or /proc/self/fd path cannot be used.
//
// Throws Error if the viewer could not be launched.
void open_photo_in_viewer(const PhotoPayload& photo);

}  // namespace ratchet::photo

#endif  // RATCHET_PHOTO_HPP
