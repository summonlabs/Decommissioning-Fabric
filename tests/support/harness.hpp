// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Minimal test harness. No third-party dependency, deterministic output, and
// per-test isolation: one failing test does not stop the suite, and the process
// exit code is non-zero if anything failed.

#ifndef DECOMMISSIONING_FABRIC_TEST_HARNESS_HPP
#define DECOMMISSIONING_FABRIC_TEST_HARNESS_HPP

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace df_test {

struct Failure {
  std::string message;
};

[[nodiscard]] inline std::string ToText(const std::string& value) { return value; }
[[nodiscard]] inline std::string ToText(std::string_view value) { return std::string(value); }
[[nodiscard]] inline std::string ToText(const char* value) { return std::string(value); }
[[nodiscard]] inline std::string ToText(bool value) { return value ? "true" : "false"; }

template <typename T>
[[nodiscard]] std::string ToText(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_convertible_v<T, long long>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_convertible_v<T, unsigned long long>) {
    return std::to_string(static_cast<unsigned long long>(value));
  } else {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  }
}

inline void Check(bool condition, const char* expression, const char* file, int line,
                  const std::string& detail = std::string()) {
  if (condition) {
    return;
  }
  std::string message = std::string(file) + ":" + std::to_string(line) +
                        ": check failed: " + expression;
  if (!detail.empty()) {
    message += " (" + detail + ")";
  }
  throw Failure{message};
}

template <typename A, typename B>
void CheckEq(const A& actual, const B& expected, const char* actual_text,
             const char* expected_text, const char* file, int line) {
  if (actual == expected) {
    return;
  }
  throw Failure{std::string(file) + ":" + std::to_string(line) + ": check failed: " +
                actual_text + " == " + expected_text + " (actual=" + ToText(actual) +
                ", expected=" + ToText(expected) + ")"};
}

template <typename A, typename B>
void CheckNe(const A& actual, const B& unexpected, const char* actual_text,
             const char* unexpected_text, const char* file, int line) {
  if (!(actual == unexpected)) {
    return;
  }
  throw Failure{std::string(file) + ":" + std::to_string(line) + ": check failed: " +
                actual_text + " != " + unexpected_text + " (both=" + ToText(actual) + ")"};
}

/// Fails the test unless the Result is an error with the expected code.
template <typename T>
void CheckErrorCode(const T& result, int expected_code, const char* text, const char* file,
                    int line) {
  if (result.ok()) {
    throw Failure{std::string(file) + ":" + std::to_string(line) + ": expected " + text +
                  " to fail with code " + std::to_string(expected_code) + " but it succeeded"};
  }
  const int actual = static_cast<int>(result.error().code);
  if (actual != expected_code) {
    throw Failure{std::string(file) + ":" + std::to_string(line) + ": " + text +
                  " failed with the wrong code: actual=" + std::to_string(actual) +
                  " expected=" + std::to_string(expected_code) + " [" +
                  result.error().to_string() + "]"};
  }
}

struct TestCase {
  std::string name;
  std::function<void()> body;
};

class Registry {
 public:
  static Registry& Instance() {
    static Registry registry;
    return registry;
  }

  void Add(std::string name, std::function<void()> body) {
    cases_.push_back(TestCase{std::move(name), std::move(body)});
  }

  [[nodiscard]] int Run(const std::string& filter) const {
    int failures = 0;
    int ran = 0;
    for (const TestCase& test : cases_) {
      if (!filter.empty() && test.name.find(filter) == std::string::npos) {
        continue;
      }
      ++ran;
      try {
        test.body();
        std::printf("PASS %s\n", test.name.c_str());
      } catch (const Failure& failure) {
        ++failures;
        std::printf("FAIL %s\n     %s\n", test.name.c_str(), failure.message.c_str());
      } catch (const std::exception& error) {
        ++failures;
        std::printf("FAIL %s\n     unexpected exception: %s\n", test.name.c_str(), error.what());
      } catch (...) {
        ++failures;
        std::printf("FAIL %s\n     unexpected non-standard exception\n", test.name.c_str());
      }
      std::fflush(stdout);
    }
    std::printf("---- %d test(s) run, %d failure(s)\n", ran, failures);
    std::fflush(stdout);
    return failures == 0 ? 0 : 1;
  }

 private:
  std::vector<TestCase> cases_;
};

}  // namespace df_test

#define DF_TEST(name)                                                          \
  static void df_test_body_##name();                                           \
  namespace {                                                                  \
  struct df_test_registrar_##name {                                            \
    df_test_registrar_##name() {                                               \
      ::df_test::Registry::Instance().Add(#name, df_test_body_##name);         \
    }                                                                          \
  };                                                                           \
  const df_test_registrar_##name df_test_registrar_instance_##name;            \
  }                                                                            \
  static void df_test_body_##name()

#define DF_CHECK(condition) ::df_test::Check((condition), #condition, __FILE__, __LINE__)

#define DF_CHECK_MSG(condition, detail) \
  ::df_test::Check((condition), #condition, __FILE__, __LINE__, (detail))

#define DF_CHECK_EQ(actual, expected) \
  ::df_test::CheckEq((actual), (expected), #actual, #expected, __FILE__, __LINE__)

#define DF_CHECK_NE(actual, unexpected) \
  ::df_test::CheckNe((actual), (unexpected), #actual, #unexpected, __FILE__, __LINE__)

#define DF_CHECK_CODE(result, code) \
  ::df_test::CheckErrorCode((result), static_cast<int>(code), #result, __FILE__, __LINE__)

#define DF_TEST_MAIN()                                        \
  int main(int argc, char** argv) {                           \
    const std::string filter = argc > 1 ? argv[1] : "";       \
    return ::df_test::Registry::Instance().Run(filter);       \
  }

#endif  // DECOMMISSIONING_FABRIC_TEST_HARNESS_HPP
