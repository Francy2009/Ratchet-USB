#include "gui_output.hpp"

#include "ratchet/gui_format.hpp"

#include <QHash>
#include <QStringList>

#include <utility>

namespace ratchet::gui {
namespace {

constexpr qsizetype kMaxBlockChars = 4096;
constexpr qsizetype kMaxFieldChars = 1024;

ParsedGuiResult fail(const QString& why) {
  ParsedGuiResult result;
  result.error = why;
  return result;
}

bool starts_a_line(const QString& text, qsizetype position) {
  return position == 0 || text.at(position - 1) == QLatin1Char('\n');
}

// Same rules as ratchet::gui_format::valid_phrase, but over QChar so the
// parser validates the value it already holds without making a std::string copy
// of a passphrase.
bool valid_phrase(const QString& phrase, qulonglong expected_words) {
  if (expected_words == 0 || phrase.isEmpty() ||
      phrase.size() > kMaxFieldChars) {
    return false;
  }
  qulonglong words = 0;
  qsizetype start = 0;
  for (;;) {
    const qsizetype space = phrase.indexOf(QLatin1Char(' '), start);
    const qsizetype end = space < 0 ? phrase.size() : space;
    if (end == start) {
      return false;
    }
    for (qsizetype i = start; i < end; ++i) {
      const QChar c = phrase.at(i);
      if (c < QLatin1Char('a') || c > QLatin1Char('z')) {
        return false;
      }
    }
    ++words;
    if (space < 0) {
      break;
    }
    start = space + 1;
  }
  return words == expected_words;
}

bool digits_only(const QString& text) {
  if (text.isEmpty()) {
    return false;
  }
  for (const QChar c : text) {
    if (c < QLatin1Char('0') || c > QLatin1Char('9')) {
      return false;
    }
  }
  return true;
}

bool parse_count(const QString& text, qulonglong& out) {
  if (!digits_only(text)) {
    return false;
  }
  bool ok = false;
  out = text.toULongLong(&ok, 10);
  return ok;
}

}  // namespace

ParsedGuiResult parseGuiResult(const QString& text,
                               const QString& expected_command) {
  if (expected_command != QLatin1String("init") &&
      expected_command != QLatin1String("passphrase")) {
    return fail(QStringLiteral("internal: unknown command for structured output"));
  }

  const QString begin = QString::fromLatin1(gui_format::kBegin);
  const QString end = QString::fromLatin1(gui_format::kEnd);
  const qsizetype begin_pos = text.indexOf(begin);
  if (begin_pos < 0 || !starts_a_line(text, begin_pos)) {
    return fail(QStringLiteral("structured result is missing"));
  }
  if (text.indexOf(begin, begin_pos + begin.size()) >= 0) {
    return fail(QStringLiteral("structured result appears more than once"));
  }
  const qsizetype end_pos = text.indexOf(end, begin_pos + begin.size());
  if (end_pos < 0) {
    return fail(QStringLiteral("structured result has no end marker"));
  }
  if (!starts_a_line(text, end_pos)) {
    return fail(QStringLiteral("structured end marker is not on its own line"));
  }
  if (text.indexOf(end, end_pos + end.size()) >= 0) {
    return fail(QStringLiteral("structured result appears more than once"));
  }

  const QString body = text.mid(begin_pos + begin.size(),
                                end_pos - (begin_pos + begin.size()));
  if (body.size() > kMaxBlockChars) {
    return fail(QStringLiteral("structured result is too large"));
  }

  QStringList lines = body.split(QLatin1Char('\n'));
  if (!lines.isEmpty() && lines.first().isEmpty()) {
    lines.removeFirst();
  }
  if (!lines.isEmpty() && lines.last().isEmpty()) {
    lines.removeLast();
  }
  if (lines.isEmpty()) {
    return fail(QStringLiteral("structured result is empty"));
  }

  QHash<QString, QString> fields;
  for (const QString& line : lines) {
    if (line.isEmpty()) {
      return fail(QStringLiteral("structured result contains an empty line"));
    }
    if (line.contains(QLatin1Char('\r'))) {
      return fail(QStringLiteral("structured result contains a CR character"));
    }
    const qsizetype equals = line.indexOf(QLatin1Char('='));
    if (equals <= 0) {
      return fail(QStringLiteral("structured result has a malformed field"));
    }
    const QString key = line.left(equals);
    const QString value = line.mid(equals + 1);
    if (key != QLatin1String("version") && key != QLatin1String("command") &&
        key != QLatin1String("status") && key != QLatin1String("source") &&
        key != QLatin1String("passphrase_words") &&
        key != QLatin1String("passphrase") &&
        key != QLatin1String("recovery_words") &&
        key != QLatin1String("recovery")) {
      return fail(QStringLiteral("structured result has an unknown field"));
    }
    if (fields.contains(key)) {
      return fail(QStringLiteral("structured result has a duplicate field"));
    }
    fields.insert(key, value);
  }

  if (!fields.contains(QStringLiteral("version")) ||
      !fields.contains(QStringLiteral("command")) ||
      !fields.contains(QStringLiteral("status"))) {
    return fail(QStringLiteral("structured result is missing version, command "
                               "or status"));
  }
  if (fields.value(QStringLiteral("version")) !=
      QString::fromLatin1(gui_format::kVersion)) {
    return fail(QStringLiteral("structured result has an unsupported version"));
  }
  if (fields.value(QStringLiteral("command")) != expected_command) {
    return fail(QStringLiteral("structured result is for a different command"));
  }

  const QString status = fields.value(QStringLiteral("status"));
  if (status == QLatin1String("cancelled")) {
    if (expected_command != QLatin1String("passphrase")) {
      return fail(QStringLiteral("this command cannot be cancelled"));
    }
    if (fields.contains(QStringLiteral("source")) ||
        fields.contains(QStringLiteral("passphrase")) ||
        fields.contains(QStringLiteral("passphrase_words")) ||
        fields.contains(QStringLiteral("recovery")) ||
        fields.contains(QStringLiteral("recovery_words"))) {
      return fail(QStringLiteral("cancelled result carries secret fields"));
    }
    ParsedGuiResult result;
    result.value.status = GuiResult::Status::Cancelled;
    result.ok = true;
    return result;
  }
  if (status != QLatin1String("ok")) {
    return fail(QStringLiteral("structured result has an unknown status"));
  }

  QString source;
  if (expected_command == QLatin1String("init")) {
    if (!fields.contains(QStringLiteral("source"))) {
      return fail(QStringLiteral("structured result is missing the init "
                                 "source"));
    }
    source = fields.value(QStringLiteral("source"));
    if (source != QLatin1String("generated") &&
        source != QLatin1String("mnemonic")) {
      return fail(QStringLiteral("structured result has an unknown init "
                                 "source"));
    }
  } else if (fields.contains(QStringLiteral("source"))) {
    return fail(QStringLiteral("structured result carries an init source for "
                               "the wrong command"));
  }

  if (!fields.contains(QStringLiteral("passphrase")) ||
      !fields.contains(QStringLiteral("passphrase_words"))) {
    return fail(QStringLiteral("structured result is missing the passphrase"));
  }
  qulonglong passphrase_words = 0;
  if (!parse_count(fields.value(QStringLiteral("passphrase_words")),
                   passphrase_words) ||
      passphrase_words < gui_format::kMinPassphraseWords ||
      passphrase_words > gui_format::kMaxPassphraseWords) {
    return fail(QStringLiteral("structured result has an invalid passphrase "
                               "word count"));
  }
  const QString passphrase = fields.value(QStringLiteral("passphrase"));
  if (!valid_phrase(passphrase, passphrase_words)) {
    return fail(QStringLiteral("structured result has a malformed passphrase"));
  }

  const bool has_recovery = fields.contains(QStringLiteral("recovery"));
  const bool has_recovery_words =
      fields.contains(QStringLiteral("recovery_words"));
  if (has_recovery != has_recovery_words) {
    return fail(QStringLiteral("structured result has an incomplete recovery "
                               "phrase"));
  }
  QString recovery;
  if (has_recovery) {
    if (expected_command != QLatin1String("init")) {
      return fail(QStringLiteral("structured result carries a recovery phrase "
                                 "for the wrong command"));
    }
    qulonglong recovery_words = 0;
    if (!parse_count(fields.value(QStringLiteral("recovery_words")),
                     recovery_words) ||
        recovery_words != gui_format::kRecoveryWords) {
      return fail(QStringLiteral("structured result has an invalid recovery "
                                 "word count"));
    }
    recovery = fields.value(QStringLiteral("recovery"));
    if (!valid_phrase(recovery, recovery_words)) {
      return fail(QStringLiteral("structured result has a malformed recovery "
                                 "phrase"));
    }
  }

  if (expected_command == QLatin1String("init")) {
    if (source == QLatin1String("generated") && !has_recovery) {
      return fail(QStringLiteral("structured result is missing the recovery "
                                 "phrase it says was generated"));
    }
    if (source == QLatin1String("mnemonic") && has_recovery) {
      return fail(QStringLiteral("structured result carries a recovery phrase "
                                 "for a restored identity"));
    }
  }

  ParsedGuiResult result;
  result.value.status = GuiResult::Status::Ok;
  result.value.passphrase = passphrase;
  result.value.recovery = std::move(recovery);
  result.ok = true;
  return result;
}

}  // namespace ratchet::gui
