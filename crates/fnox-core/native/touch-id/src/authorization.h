#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace fnox {

enum class TouchIdStatus {
  kSuccess,
  kDenied,
  kCancelled,
  kUnavailable,
};

struct TouchIdError {
  TouchIdStatus status = TouchIdStatus::kSuccess;
  int os_status = 0;
  std::string detail;
};

class TouchIdAuthorization final {
 public:
  explicit TouchIdAuthorization(bool system_verification = false);
  ~TouchIdAuthorization();

  TouchIdAuthorization(const TouchIdAuthorization&) = delete;
  TouchIdAuthorization& operator=(const TouchIdAuthorization&) = delete;
  TouchIdAuthorization(TouchIdAuthorization&&) = delete;
  TouchIdAuthorization& operator=(TouchIdAuthorization&&) = delete;

  bool AuthenticateWithEvents(std::string_view reason, TouchIdError& error,
                              const std::function<void()>& process_events);
  void* AuthenticationContext() const;
  void Invalidate();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace fnox
