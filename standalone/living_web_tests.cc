// Living Web — Test Suite
//
// A minimal, self-registering test framework (no gtest dependency). The base
// ships the framework and the runner only. Each per-spec branch adds the
// includes, helpers, and TEST() blocks it needs — so the suite grows one spec
// at a time and every test is introduced by the PR that implements its spec.

#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ============================================================
// Minimal test framework
// ============================================================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static std::vector<std::string> failures;

#define TEST(name) \
  static void test_##name(); \
  static bool test_##name##_registered = (register_test(#name, test_##name), true); \
  static void test_##name()

#define EXPECT_TRUE(expr) do { \
  if (!(expr)) { \
    std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))
#define EXPECT_EQ(a, b) do { \
  auto _a = (a); auto _b = (b); \
  if (_a != _b) { \
    std::cerr << "  FAIL: " << #a << " == " << #b << " (" << _a << " != " << _b << ") at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_NE(a, b) do { \
  if ((a) == (b)) { \
    std::cerr << "  FAIL: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_GT(a, b) do { \
  if (!((a) > (b))) { \
    std::cerr << "  FAIL: " << #a << " > " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

struct TestEntry {
  std::string name;
  std::function<void()> fn;
};
static std::vector<TestEntry>& test_registry() {
  static std::vector<TestEntry> r;
  return r;
}
static void register_test(const std::string& name, std::function<void()> fn) {
  test_registry().push_back({name, fn});
}

// ============================================================
// Test cases
// ============================================================
//
// Populated per spec. Each per-spec branch inserts its includes above, its
// helpers here, and its TEST() blocks below this banner.

// ============================================================
// Main
// ============================================================

int main(int argc, char** argv) {
  std::cout << "Living Web — Test Suite\n";
  std::cout << "=======================\n\n";

  for (auto& entry : test_registry()) {
    tests_run++;
    std::cout << "  [RUN ] " << entry.name << std::flush;
    try {
      entry.fn();
      tests_passed++;
      std::cout << " [PASS]\n";
    } catch (const std::exception& e) {
      tests_failed++;
      failures.push_back(entry.name);
      std::cout << " [FAIL]\n";
    }
  }

  std::cout << "\n=======================\n";
  std::cout << "Tests run: " << tests_run
            << " | Passed: " << tests_passed
            << " | Failed: " << tests_failed << "\n";

  if (!failures.empty()) {
    std::cout << "\nFailed tests:\n";
    for (const auto& f : failures)
      std::cout << "  - " << f << "\n";
  }

  return tests_failed > 0 ? 1 : 0;
}
