#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace fnox {

enum class PreviewStatus {
  kSuccess,
  kDenied,
  kCancelled,
  kUnavailable,
};

struct PreviewError {
  PreviewStatus status = PreviewStatus::kSuccess;
  int os_status = 0;
  std::string detail;
};

class PreviewAuthorization final {
 public:
  explicit PreviewAuthorization(bool system_verification = false);
  ~PreviewAuthorization();

  PreviewAuthorization(const PreviewAuthorization&) = delete;
  PreviewAuthorization& operator=(const PreviewAuthorization&) = delete;
  PreviewAuthorization(PreviewAuthorization&&) = delete;
  PreviewAuthorization& operator=(PreviewAuthorization&&) = delete;

  bool AuthenticateWithEvents(std::string_view reason, PreviewError& error,
                              const std::function<void()>& process_events);
  void* AuthenticationContext() const;
  void Invalidate();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace fnox
