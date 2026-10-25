#ifndef RATCHET_TEST_SUPPORT_HPP
#define RATCHET_TEST_SUPPORT_HPP

// A minimal test harness. libsodium is the project's only dependency and that
// is worth keeping true for the tests too, so this is a small registry of test
// functions plus a handful of assertion macros rather than a framework.

#include <array>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

namespace ratchet::test {

inline constexpr std::size_t kMaxTests = 1024;

struct TestCase {
  const char* name;
  void (*body)();
};

// A fixed array and a function pointer, rather than a std::vector of
// std::function: registration happens during static initialisation, where an
// allocation that throws cannot be caught (and is a lint error for good
// reason). The ceiling is far above the number of tests in this tree.
inline std::array<TestCase, kMaxTests>& registry() {
  static std::array<TestCase, kMaxTests> tests{};
  return tests;
}

inline std::size_t& registry_size() {
  static std::size_t size = 0;
  return size;
}

struct Registrar {
  Registrar(const char* name, void (*body)()) noexcept {
    std::size_t& size = registry_size();
    if (size >= kMaxTests) {
      std::abort();
    }
    registry()[size++] = TestCase{name, body};
  }
};

class Failure : public std::exception {
 public:
  explicit Failure(std::string what) : what_(std::move(what)) {}
  const char* what() const noexcept override { return what_.c_str(); }

 private:
  std::string what_;
};

inline int run_all(const std::string& filter = {}, bool list_only = false) {
  const std::size_t total = registry_size();
  std::size_t run = 0;
  std::size_t failed = 0;
  for (std::size_t i = 0; i < total; ++i) {
    const TestCase& test = registry()[i];
    if (!filter.empty() && std::string(test.name).find(filter) == std::string::npos) {
      continue;
    }
    ++run;
    if (list_only) {
      std::cout << test.name << "\n";
      continue;
    }
    try {
      test.body();
      std::cout << "  ok   " << test.name << "\n";
    } catch (const std::exception& e) {
      std::cout << "  FAIL " << test.name << "\n       " << e.what() << "\n";
      ++failed;
    }
  }
  if (list_only) {
    return 0;
  }
  std::cout << "\n" << run - failed << "/" << run << " tests passed\n";
  return failed == 0 ? 0 : 1;
}

}  // namespace ratchet::test

#define RATCHET_CONCAT_INNER(a, b) a##b
#define RATCHET_CONCAT(a, b) RATCHET_CONCAT_INNER(a, b)

#define TEST(name)                                                       \
  static void RATCHET_CONCAT(test_body_, __LINE__)();                    \
  static const ::ratchet::test::Registrar RATCHET_CONCAT(test_reg_,      \
                                                         __LINE__)(      \
      name, RATCHET_CONCAT(test_body_, __LINE__));                       \
  static void RATCHET_CONCAT(test_body_, __LINE__)()

#define CHECK(cond)                                                         \
  do {                                                                      \
    if (!(cond)) {                                                          \
      std::ostringstream oss;                                               \
      oss << __FILE__ << ":" << __LINE__ << ": CHECK(" #cond ") failed";    \
      throw ::ratchet::test::Failure(oss.str());                            \
    }                                                                       \
  } while (false)

#define CHECK_EQ(a, b)                                                      \
  do {                                                                      \
    const auto& lhs_ = (a);                                                 \
    const auto& rhs_ = (b);                                                 \
    if (!(lhs_ == rhs_)) {                                                  \
      std::ostringstream oss;                                               \
      oss << __FILE__ << ":" << __LINE__ << ": CHECK_EQ(" #a ", " #b ")"    \
          << " failed: " << lhs_ << " != " << rhs_;                         \
      throw ::ratchet::test::Failure(oss.str());                            \
    }                                                                       \
  } while (false)

// Asserts that `expr` throws ratchet::Error.
#define CHECK_THROWS(expr)                                                  \
  do {                                                                      \
    bool threw_ = false;                                                    \
    try {                                                                   \
      (void)(expr);                                                         \
    } catch (const ::ratchet::Error&) {                                     \
      threw_ = true;                                                        \
    }                                                                       \
    if (!threw_) {                                                          \
      std::ostringstream oss;                                               \
      oss << __FILE__ << ":" << __LINE__ << ": expected " #expr             \
          << " to throw ratchet::Error";                                    \
      throw ::ratchet::test::Failure(oss.str());                            \
    }                                                                       \
  } while (false)

#endif  // RATCHET_TEST_SUPPORT_HPP
