#import <LocalAuthentication/LocalAuthentication.h>
#include <atomic>
#include "authorization.h"
#include "preview-mode.h"

namespace {
bool gFnoxPreviewAccepted = false;
}

bool FnoxPreviewAcceptTouchId() {
  if (fnox::IsSystemVerification()) return false;
  gFnoxPreviewAccepted = true;
  return true;
}

namespace fnox {
struct TouchIdAuthorization::Impl {
  LAContext* context = [LAContext new];
  bool system_verification = false;
  bool cancelled = false;
};
TouchIdAuthorization::TouchIdAuthorization(bool system_verification)
    : impl_(std::make_unique<Impl>()) {
  impl_->system_verification = system_verification;
}
TouchIdAuthorization::~TouchIdAuthorization() { Invalidate(); }
void TouchIdAuthorization::Invalidate() {
  impl_->cancelled = true;
  [impl_->context invalidate];
}
void* TouchIdAuthorization::AuthenticationContext() const {
  return (__bridge void*)impl_->context;
}
bool TouchIdAuthorization::AuthenticateWithEvents(std::string_view reason, TouchIdError& error,
                                                  const std::function<void()>& process_events) {
  if (!impl_->system_verification && !IsSystemVerification()) {
    while (!impl_->cancelled && !gFnoxPreviewAccepted) {
      process_events();
      [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    if (impl_->cancelled) error.status = TouchIdStatus::kCancelled;
    return !impl_->cancelled && gFnoxPreviewAccepted;
  }
  NSError* availability = nil;
  impl_->context.localizedFallbackTitle = @"";
  if (![impl_->context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                   error:&availability]) {
    error.status = TouchIdStatus::kUnavailable;
    error.os_status = static_cast<int>(availability.code);
    error.detail = availability.localizedDescription.UTF8String ?: "Touch ID unavailable";
    return false;
  }
  struct Result {
    std::atomic<bool> done{false};
    bool approved = false;
    int code = 0;
    std::string detail;
  };
  auto result = std::make_shared<Result>();
  NSString* localizedReason = [[NSString alloc] initWithBytes:reason.data()
                                                        length:reason.size()
                                                      encoding:NSUTF8StringEncoding];
  if (localizedReason.length == 0) localizedReason = @"authorize this Fnox Keychain request";
  impl_->context.localizedReason = localizedReason;
  [impl_->context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                 localizedReason:localizedReason
                           reply:^(BOOL approved, NSError* failure) {
                             result->approved = approved;
                             if (failure) {
                               result->code = static_cast<int>(failure.code);
                               result->detail =
                                   failure.localizedDescription.UTF8String ?: "Verification failed";
                             }
                             result->done.store(true, std::memory_order_release);
                           }];
  while (!impl_->cancelled && !result->done.load(std::memory_order_acquire)) {
    process_events();
    [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
  }
  if (impl_->cancelled) {
    error.status = TouchIdStatus::kCancelled;
    return false;
  }
  error.detail = result->detail;
  error.os_status = result->code;
  if (result->approved) {
    error.status = TouchIdStatus::kSuccess;
  } else {
    switch (result->code) {
      case LAErrorUserCancel:
      case LAErrorAppCancel:
      case LAErrorSystemCancel:
        error.status = TouchIdStatus::kCancelled;
        break;
      case LAErrorAuthenticationFailed:
      case LAErrorUserFallback:
        error.status = TouchIdStatus::kDenied;
        break;
      default:
        error.status = TouchIdStatus::kUnavailable;
        break;
    }
  }
  return result->approved;
}

}  // namespace fnox
