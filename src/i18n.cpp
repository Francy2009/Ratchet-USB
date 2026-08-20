#include "ratchet/i18n.hpp"

#include <array>
#include <cstdlib>

namespace ratchet::i18n {
namespace {

constexpr std::size_t kCount = static_cast<std::size_t>(Str::Count);

constexpr std::array<std::string_view, kCount> kEnglish = {
#define RATCHET_I18N_EN(id, en, it) std::string_view(en),
    RATCHET_I18N_STRINGS(RATCHET_I18N_EN)
#undef RATCHET_I18N_EN
};

constexpr std::array<std::string_view, kCount> kItalian = {
#define RATCHET_I18N_IT(id, en, it) std::string_view(it),
    RATCHET_I18N_STRINGS(RATCHET_I18N_IT)
#undef RATCHET_I18N_IT
};

// Reads an environment variable, treating unset and empty the same way.
std::string_view env(const char* name) {
  const char* value = std::getenv(name);
  return (value == nullptr) ? std::string_view() : std::string_view(value);
}

}  // namespace

std::string_view t(Lang lang, Str id) {
  const auto index = static_cast<std::size_t>(id);
  if (index >= kCount) {
    return {};
  }
  return (lang == Lang::It) ? kItalian[index] : kEnglish[index];
}

bool is_valid_choice(std::string_view choice) {
  return choice == "en" || choice == "it";
}

Lang detect(std::string_view choice) {
  if (choice == "it") {
    return Lang::It;
  }
  if (choice == "en") {
    return Lang::En;
  }
  // LC_ALL wins over LANG, as everywhere else. Both are only checked for the
  // prefix an Italian locale starts with -- "it_IT.UTF-8", "it" -- and never
  // parsed further.
  for (const char* name : {"LC_ALL", "LANG"}) {
    const std::string_view value = env(name);
    if (value.empty()) {
      continue;
    }
    return value.starts_with("it") ? Lang::It : Lang::En;
  }
  return Lang::En;
}

}  // namespace ratchet::i18n
