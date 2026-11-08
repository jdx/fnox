#pragma once
namespace fnox {
enum class ApprovalReadinessStatus {
  kWaiting,
  kReady,
  kCancelled,
  kUnavailable
};
}  // namespace fnox
