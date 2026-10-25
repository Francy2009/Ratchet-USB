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
// open_in_file_manager() is the only function with OS side-effects.

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

// Whether `ext` names a type a desktop may run rather than display. The
// default-application dispatch is by extension, so a verified but hostile
// sender could otherwise hand over a ".desktop" or a shell script and have the
// desktop execute it when the receiver presses "open". open_in_file_manager()
// refuses these; the bytes can still be saved and inspected by hand.
//
// `ext` is expected in the sanitised form FilePayload::ext carries (lowercase,
// [a-z0-9], no leading dot).
bool is_dangerous_extension(std::string_view ext);

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

// Creates the private staging folder and the detached helper that removes it,
// if they do not exist yet. Idempotent.
//
// A front end calls this before it opens the vault, so the long-lived helper
// is forked from a process that holds no key material: after the fork the two
// share no secret pages, and the helper can outlive the session without
// keeping a copy of the keys. open_in_file_manager() calls it too, so the
// order is a hardening measure rather than a correctness requirement.
void prepare_staging();

// Removes the staging folder now, if it exists. Idempotent.
//
// A front end calls this as it exits so the decrypted file is gone the moment
// ratchet-usb closes, rather than waiting for the detached helper -- which a
// session teardown can kill, and which deliberately keeps a one-shot `recv`
// folder alive for a short grace period. Safe to call when nothing was staged.
void cleanup_staging();

// Stages `file` in a private temporary folder and opens that folder in the
// system's file manager, without writing the file to durable storage.
//
// Implementation (Linux):
//  1. Creates a private directory under $XDG_RUNTIME_DIR (a per-user tmpfs
//     cleared at logout), or a 0700 directory created with mkdtemp() under
//     $TMPDIR (or /tmp) when that is unavailable, and a 0600 file with the
//     correct extension inside it.
//  2. Writes the file bytes into it.
//  3. Forks a child that detaches and exec()s "xdg-open <folder>".
//  4. The parent waits for xdg-open, which only asks the desktop to open the
//     folder and exits quickly.
//  5. A detached helper removes the folder when ratchet-usb exits, so the
//     plaintext does not outlive the session. A caller that exits at once (the
//     `recv` command) still keeps the folder for a short minimum so the
//     desktop can draw it. If no helper can be forked, the folder is removed
//     on the ordinary exit paths instead.
//
// The path passed to xdg-open is a real filesystem path: the file manager is
// usually started as a separate (often sandboxed) process that does not inherit
// this process's file descriptors, so a memfd or /proc/self/fd path cannot be
// used.
//
// Throws Error if the folder could not be opened, or if `file.ext` names a type
// the desktop may execute (see is_dangerous_extension()).
void open_in_file_manager(const FilePayload& file);

// Stages `file` in the private temporary folder and returns the path of the
// staged file, without opening anything. This is the staging half of
// open_in_file_manager(), exposed so a front end that has no terminal (the GUI
// drives recv as a child process) can put the file on screen and let the user
// open the folder itself.
//
// The folder is still the session's private staging directory and is removed by
// the same detached helper: the caller must use the path before that happens.
//
// Throws Error on failure, or if `file.ext` names a type the desktop may execute
// (see is_dangerous_extension()).
std::string stage_file(const FilePayload& file);

}  // namespace ratchet::file

#endif  // RATCHET_FILE_HPP
