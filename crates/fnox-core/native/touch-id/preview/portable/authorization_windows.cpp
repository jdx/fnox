#include <UserConsentVerifierInterop.h>
#include <roapi.h>
#include <windows.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>

#include <QApplication>
#include <QTimer>
#include <QWidget>

#include "authorization.h"

namespace fnox::portable {
namespace {
using VerifyResult =
    winrt::Windows::Security::Credentials::UI::UserConsentVerificationResult;
using Operation = winrt::Windows::Foundation::IAsyncOperation<VerifyResult>;
using AsyncStatus = winrt::Windows::Foundation::AsyncStatus;

// Poll the asynchronous OS operation on the UI thread. No worker callback owns
// a window pointer, and cancellation stops observation before dismissing the
// UI.
class WindowsVerifier final : public QObject, public Authorization {
 public:
  WindowsVerifier() {
    timer_.setInterval(50);
    connect(&timer_, &QTimer::timeout, this, [this] {
      try {
        const auto status = operation_.Status();
        if (status == AsyncStatus::Started) return;
        if (status == AsyncStatus::Completed &&
            operation_.GetResults() == VerifyResult::Verified)
          finish(Result::Verified, {});
        else
          finish(Result::Denied, "Windows verification was not successful.");
      } catch (const winrt::hresult_error&) {
        finish(Result::Error, "Windows verification did not complete.");
      }
    });
  }
  ~WindowsVerifier() override {
    cancel();
    if (initialized_) RoUninitialize();
  }
  void start(Completion completion) override {
    cancel();
    completion_ = std::move(completion);
    try {
      if (!initialized_) {
        const HRESULT hr = RoInitialize(RO_INIT_SINGLETHREADED);
        if (hr != RPC_E_CHANGED_MODE) winrt::check_hresult(hr);
        initialized_ = SUCCEEDED(hr);
      }
      QWidget* window = QApplication::activeModalWidget();
      if (!window) window = QApplication::activeWindow();
      if (!window) {
        finish(Result::Unavailable, "The preview must be the active window.");
        return;
      }
      // This desktop interface is available starting with Windows build 22000.
      auto interop = winrt::get_activation_factory<
          winrt::Windows::Security::Credentials::UI::UserConsentVerifier,
          IUserConsentVerifierInterop>();
      const winrt::hstring reason(
          L"Verify this Fnox preview. No credentials will be read.");
      winrt::check_hresult(interop->RequestVerificationForWindowAsync(
          reinterpret_cast<HWND>(window->winId()),
          static_cast<HSTRING>(winrt::get_abi(reason)),
          winrt::guid_of<Operation>(), winrt::put_abi(operation_)));
      timer_.start();
    } catch (const winrt::hresult_error&) {
      finish(Result::Unavailable,
             "Windows Hello verification requires a supported Windows 11 "
             "session.");
    }
  }
  void cancel() override {
    timer_.stop();
    completion_ = {};
    if (operation_) {
      try {
        operation_.Cancel();
      } catch (const winrt::hresult_error&) {
      }
      operation_ = nullptr;
    }
  }

 private:
  void finish(Result result, std::string message) {
    auto callback = std::move(completion_);
    cancel();
    if (callback) callback(result, std::move(message));
  }
  QTimer timer_;
  Operation operation_{nullptr};
  Completion completion_;
  bool initialized_ = false;
};
}  // namespace
std::unique_ptr<Authorization> make_authorization(bool simulate) {
  if (simulate) return make_simulated_authorization();
  return std::make_unique<WindowsVerifier>();
}
}  // namespace fnox::portable
