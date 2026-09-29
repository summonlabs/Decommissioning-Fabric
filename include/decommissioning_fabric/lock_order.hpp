// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Documented lock acquisition order, enforced in Debug builds.
//
//   Level 5  MutationSerialiser  (one writer at a time)
//   Level 4  EngineIndex         (in-memory index, shared for readers)
//   Level 3  DurableStore        (store slot + sequence)
//   Level 2  StoreDirectory      (directory handle / reparse validation)
//   Level 1  WriterLock          (OS file lock)
//
// A thread may acquire a level strictly below the current top of its own stack.
// Any non-decreasing acquisition is a lock-order inversion: it is recorded and,
// in Debug builds, aborts immediately rather than being left to become a
// production deadlock.
//
// The stack is THREAD LOCAL, not per-validator-instance. That is the only
// correct model: the ordering constraint is about the locks one thread holds at
// one moment, and two engines in one process share the same lock levels. A
// per-instance record would make two threads inside two different engines look
// like one thread acquiring level 5 twice, and would race on the stack.

#ifndef DECOMMISSIONING_FABRIC_LOCK_ORDER_HPP
#define DECOMMISSIONING_FABRIC_LOCK_ORDER_HPP

#include <atomic>
#include <cstddef>

namespace decommissioning_fabric {

inline constexpr int kLockLevelMutationSerialiser = 5;
inline constexpr int kLockLevelEngineIndex = 4;
inline constexpr int kLockLevelDurableStore = 3;
inline constexpr int kLockLevelStoreDirectory = 2;
inline constexpr int kLockLevelWriterLock = 1;

/// Record of the locks the CALLING THREAD currently holds.
///
/// Every instance is a view onto the same per-thread state, so a validator is a
/// cheap handle rather than a piece of mutable state that has to be shared or
/// copied. The inversion count is also per thread, so one thread's deliberate
/// probe cannot make another thread's evidence look bad.
class LockOrderValidator {
 public:
  static constexpr std::size_t kMaxDepth = 16;

  /// True when acquiring \p level from this thread's current stack would invert
  /// the documented order. Pure predicate: it never mutates and never aborts, so
  /// a test can prove detection without provoking a crash.
  [[nodiscard]] bool would_invert(int level) const noexcept;

  void Acquire(int level);
  void Release(int level);

  [[nodiscard]] int depth() const noexcept;
  [[nodiscard]] int top() const noexcept;

  /// Inversions this thread has recorded.
  [[nodiscard]] std::size_t recorded_inversions() const noexcept;

 private:
  struct ThreadState {
    int stack[kMaxDepth]{};
    std::size_t depth{0};
    std::size_t inversions{0};
  };

  [[nodiscard]] static ThreadState& State() noexcept {
    static thread_local ThreadState state;
    return state;
  }
};

/// RAII guard. Acquires on construction and releases on destruction. A null
/// validator makes the guard a no-op, which is what a component that is not given
/// a validator should do rather than inventing one.
class LockOrderGuard {
 public:
  LockOrderGuard(LockOrderValidator* validator, int level) noexcept
      : validator_(validator), level_(level) {
    if (validator_ != nullptr) {
      validator_->Acquire(level_);
    }
  }
  ~LockOrderGuard() {
    if (validator_ != nullptr) {
      validator_->Release(level_);
    }
  }

  LockOrderGuard(const LockOrderGuard&) = delete;
  LockOrderGuard& operator=(const LockOrderGuard&) = delete;
  LockOrderGuard(LockOrderGuard&&) = delete;
  LockOrderGuard& operator=(LockOrderGuard&&) = delete;

 private:
  LockOrderValidator* validator_;
  int level_;
};

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_LOCK_ORDER_HPP
