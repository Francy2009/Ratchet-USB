#ifndef RATCHET_TEST_SUPPORT_HPP
#define RATCHET_TEST_SUPPORT_HPP

// A minimal test harness. libsodium is the project's only dependency and that
// is worth keeping true for the tests too, so this is a small registry of test
// functions plus a handful of assertion macros rather than a framework.

#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace ratchet::test {

struct TestCase {
  std::string name;
  std::function<void()> body;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> body) {
    registry().push_back({name, std::move(body)});
  }
};

class Failure : public std::exception {
 public:
  explicit Failure(std::string what) : what_(std::move(what)) {}
  const char* what() const noexcept override { return what_.c_str(); }

 private:
  std::string what_;
};

inline int run_all() {
  std::size_t failed = 0;
  for (const TestCase& test : registry()) {
    try {
      test.body();
      std::cout << "  ok   " << test.name << "\n";
    } catch (const std::exception& e) {
      std::cout << "  FAIL " << test.name << "\n       " << e.what() << "\n";
      ++failed;
    }
  }
  std::cout << "\n" << registry().size() - failed << "/" << registry().size()
            << " tests passed\n";
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
