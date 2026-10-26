#include "ratchet/gui_format.hpp"

#include "ratchet/passphrase.hpp"

namespace ratchet::gui_format {
namespace {

static_assert(kMinPassphraseWords == passphrase::kMinWords,
              "GUI format and passphrase generation disagree on the minimum");
static_assert(kMaxPassphraseWords == passphrase::kMaxWords,
              "GUI format and passphrase generation disagree on the maximum");

bool valid_status(std::string_view status) {
  return status == "ok" || status == "cancelled";
}

bool valid_command(std::string_view command) {
  return command == "init" || command == "passphrase";
}

// Everything is validated before the first byte is written, so an invalid
// result leaves no partial block behind. Only the stream itself can fail after
// that point.
bool valid_result(const Result& result) {
  if (!valid_command(result.command) || !valid_status(result.status)) {
    return false;
  }
  if (result.status == "cancelled") {
    return result.command == "passphrase" && result.source.empty() &&
           result.passphrase.empty() && result.passphrase_words == 0 &&
           result.recovery.empty() && result.recovery_words == 0;
  }

  if (result.passphrase_words < kMinPassphraseWords ||
      result.passphrase_words > kMaxPassphraseWords ||
      !valid_phrase(result.passphrase, result.passphrase_words)) {
    return false;
  }

  if (result.command == "passphrase") {
    return result.source.empty() && result.recovery.empty() &&
           result.recovery_words == 0;
  }

  // init: the source decides whether a recovery phrase must be present.
  if (result.source == "generated") {
    return result.recovery_words == kRecoveryWords &&
           valid_phrase(result.recovery, result.recovery_words);
  }
  if (result.source == "mnemonic") {
    return result.recovery.empty() && result.recovery_words == 0;
  }
  return false;
}

}  // namespace

bool write_result(std::ostream& os, const Result& result) {
  if (!os.good() || !valid_result(result)) {
    return false;
  }

  os << kBegin << '\n'
     << "version=" << kVersion << '\n'
     << "command=" << result.command << '\n'
     << "status=" << result.status << '\n';
  if (result.status == "ok") {
    if (result.command == "init") {
      os << "source=" << result.source << '\n';
    }
    os << "passphrase_words=" << result.passphrase_words << '\n'
       << "passphrase=" << result.passphrase << '\n';
    if (!result.recovery.empty()) {
      os << "recovery_words=" << result.recovery_words << '\n'
         << "recovery=" << result.recovery << '\n';
    }
  }
  os << kEnd << '\n';
  return os.good();
}

}  // namespace ratchet::gui_format
