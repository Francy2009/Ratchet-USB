// file.hpp — encrypted file sharing for Ratchet-USB.
//
// Any file -- an image, a document, a spreadsheet, an executable -- travels
// through exactly the same Double/Triple Ratchet pipeline as a text message.
// The only thing this module adds is a thin framing layer (a single type-byte
// prefix) that lets the receiver distinguish a file payload from a text payload
// before presenting the appropriate UI.
//
// Wire contract
// ─────────────
// The `plaintext` that session::send() encrypts is one of:
//
//   Text payload  (existing, unchanged):
//     arbitrary bytes  — any message where byte[0] != kPayloadTypeFile
//
//   File payload:
//     [0x02]  one byte — kPayloadTypeFile marker
//     [u32le] four bytes — length of the extension string (e.g. 3 for "jpg")
//     [bytes] extension characters, no NUL
//     [bytes] raw file bytes to end of string
//
// 0x02 is STX (Start of Text) in ASCII and will never appear as the first
// character of a user-typed message, so the two cases are unambiguous.
//
// Images are files like any other. JPEG and PNG are still recognised by their
// magic bytes so an image keeps the right extension for the viewer even when
// the file was named something else. The framing is unchanged from the earlier
// image-only version, so images sent by an older build still decode.
//
// Nothing in this header touches the ratchet state, the vault or the disk.
// open_in_default_app() is the only function with OS side-effects.

#ifndef RATCHET_FILE_HPP
#define RATCHET_FILE_HPP

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ratchet::file {

// Maximum raw file size accepted by load_file().
// Must stay well below message::kMaxPlaintextBytes (4 MiB) once the framing
// header is added (5 + ext_len bytes).
inline constexpr std::size_t kMaxFileBytes =
    std::size_t{4} * 1024u * 1024u - 64u;

// Type-byte placed at offset 0 of every file payload.
inline constexpr uint8_t kPayloadTypeFile = 0x02u;

// Holds a decoded file ready to be shown or written to a viewer.
// `bytes` are the raw file contents; `ext` is a sanitised, lowercase extension
// without the leading dot ("jpg", "png", "pdf", "odt", "bin", ...).
struct FilePayload {
  std::string          ext;    // lowercase, [a-z0-9], at most 16 characters
  std::vector<uint8_t> bytes;  // raw file bytes
};

// Reads a file from the host filesystem.
//
// Validates:
//  – the path points to a regular file owned by the current user
//  – the file size does not exceed kMaxFileBytes
//
// Any format is accepted; the extension used on the wire comes from
// extension_for(). Returns the raw bytes on success; throws ratchet::Error on
// any failure. The read is done without any permanent write to the USB drive or
// host disk.
std::vector<uint8_t> load_file(const std::filesystem::path& path);

// The extension to advertise for `raw`, given the file it came from.
//
// A JPEG or PNG is recognised by its magic bytes and gets "jpg" or "png" even
// if it was named something else. Anything else uses the file name's extension,
// lowercased and restricted to [a-z0-9] (at most 16 characters); when the name
// has no usable extension the result is "bin". Never returns an empty string.
std::string extension_for(const std::filesystem::path& path,
                          const std::vector<uint8_t>& raw);

// Packs raw file bytes and their extension into the payload format that
// session::send() will encrypt:
//   [0x02][u32-LE ext_len][ext bytes][file bytes]
//
// The returned string becomes the `plaintext` argument for session::send().
// No copy of the file data is left behind by this function.
std::string encode_file_payload(const std::vector<uint8_t>& raw,
                                std::string_view ext);

// Returns a FilePayload if `plaintext[0] == kPayloadTypeFile`.
// Returns nullopt for ordinary text messages (byte[0] != 0x02).
// The extension is sanitised on the way in, so a sender cannot choose a path
// the receiver's viewer would be tricked into following.
// Throws Error if the header is present but the payload is structurally
// invalid (truncated length field, oversized extension, empty body, etc.).
std::optional<FilePayload> decode_file_payload(const std::string& plaintext);

// Opens `file` in the system's default application without writing the file to
// durable storage.
//
// Implementation (Linux):
//  1. Creates a 0600 file with the correct extension under $XDG_RUNTIME_DIR
//     (a tmpfs cleared at logout), or /tmp when that is unavailable.
//  2. Writes the file bytes into it.
//  3. Forks a child that detaches and exec()s "xdg-open <real path>".
//  4. The parent waits for xdg-open, which only asks the desktop to open the
//     path and exits quickly.
//  5. A detached helper unlinks the staged file after a short grace period.
//
// The path passed to xdg-open is a real filesystem path: the application is
// usually started as a separate (often sandboxed) process that does not inherit
// this process's file descriptors, so a memfd or /proc/self/fd path cannot be
// used.
//
// Throws Error if the application could not be launched.

void open_in_default_app(const FilePayload& file);

}  // namespace ratchet::file

#endif  // RATCHET_FILE_HPP
