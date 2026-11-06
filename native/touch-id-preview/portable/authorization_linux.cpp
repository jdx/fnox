#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusServiceWatcher>
#include <QTimer>
#include <QUuid>

#include "authorization.h"

namespace fnox::portable {
namespace {
constexpr auto kService = "net.reactivated.Fprint";
constexpr auto kDeviceInterface = "net.reactivated.Fprint.Device";
constexpr int kTimeoutMs = 30000;

class FprintdVerifier final : public QObject, public Authorization {
  Q_OBJECT
 public:
  FprintdVerifier()
      : connection_name_("fnox-preview-" + QUuid::createUuid().toString()),
        bus_(QDBusConnection::connectToBus(QDBusConnection::SystemBus,
                                           connection_name_)) {
    timeout_.setSingleShot(true);
    connect(&timeout_, &QTimer::timeout, this, [this] {
      finish(Result::Denied, "Fingerprint verification timed out.");
    });
  }
  ~FprintdVerifier() override { cancel(); }
  void start(Completion completion) override {
    completion_ = std::move(completion);
    if (!bus_.isConnected()) {
      finish(Result::Unavailable, "The system D-Bus is unavailable.");
      return;
    }
    timeout_.start(kTimeoutMs);
    auto message = QDBusMessage::createMethodCall(
        kService, "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager", "GetDefaultDevice");
    watch(bus_.asyncCall(message), [this](const QDBusMessage& reply) {
      QDBusPendingReply<QDBusObjectPath> result(reply);
      if (result.isError()) {
        finish(Result::Unavailable, "No fprintd reader is available.");
        return;
      }
      device_ = result.value().path();
      // Bind subsequent methods and signals to this exact daemon instance.
      owner_ = reply.service();
      service_watcher_ = std::make_unique<QDBusServiceWatcher>(
          owner_, bus_, QDBusServiceWatcher::WatchForUnregistration, this);
      connect(service_watcher_.get(), &QDBusServiceWatcher::serviceUnregistered,
              this, [this] {
                finish(Result::Unavailable,
                       "The fingerprint service disconnected.");
              });
      watch(call("Claim", {QString()}), [this](const QDBusMessage& reply) {
        if (reply.type() == QDBusMessage::ErrorMessage) {
          finish(Result::Unavailable,
                 "Could not claim the fingerprint reader. Check enrollment and "
                 "permissions.");
          return;
        }
        claimed_ = true;
        if (!bus_.connect(owner_, device_, kDeviceInterface, "VerifyStatus",
                          this, SLOT(verifyStatus(QString, bool)))) {
          finish(Result::Error, "Could not observe fingerprint verification.");
          return;
        }
        // Mark before dispatch: a status signal can precede the method reply.
        started_ = true;
        watch(call("VerifyStart", {QStringLiteral("any")}),
              [this](const QDBusMessage& reply) {
                if (reply.type() == QDBusMessage::ErrorMessage)
                  finish(Result::Unavailable,
                         "Fingerprint verification could not start. Check "
                         "enrollment.");
              });
      });
    });
  }
  void cancel() override {
    if (finished_) return;
    finished_ = true;
    timeout_.stop();
    completion_ = {};
    if (!device_.isEmpty()) {
      bus_.disconnect(owner_, device_, kDeviceInterface, "VerifyStatus", this,
                      SLOT(verifyStatus(QString, bool)));
      if (started_) call("VerifyStop");
      if (claimed_) call("Release");
    }
    // A private connection makes closing the dialog safe even while Claim is
    // still pending: fprintd releases the disconnected client's device claim.
    if (service_watcher_) {
      service_watcher_->disconnect(this);
      service_watcher_->setConnection(QDBusConnection(QString()));
      service_watcher_.reset();
    }
    QDBusConnection::disconnectFromBus(connection_name_);
    bus_ = QDBusConnection(QString());
  }
 private slots:
  void verifyStatus(const QString& result, bool done) {
    if (finished_ || !claimed_ || !started_) return;
    if (result == "verify-match")
      finish(Result::Verified, {});
    else if (result == "verify-no-match")
      finish(Result::Denied, "Fingerprint did not match.");
    else if (done || result == "verify-disconnected" ||
             result == "verify-unknown-error")
      finish(Result::Error, "Fingerprint verification ended without a match.");
    // Nonterminal retry statuses leave verification active until the deadline.
  }

 private:
  QDBusPendingCall call(const QString& method,
                        const QList<QVariant>& arguments = {}) {
    auto message = QDBusMessage::createMethodCall(owner_, device_,
                                                  kDeviceInterface, method);
    message.setArguments(arguments);
    return bus_.asyncCall(message);
  }
  void watch(QDBusPendingCall call,
             std::function<void(const QDBusMessage&)> callback) {
    auto* watcher = new QDBusPendingCallWatcher(call, this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this,
             callback = std::move(callback)](QDBusPendingCallWatcher* watcher) {
              const auto reply = watcher->reply();
              watcher->deleteLater();
              if (!finished_) callback(reply);
            });
  }
  void finish(Result result, std::string message) {
    auto callback = std::move(completion_);
    cancel();
    if (callback) callback(result, std::move(message));
  }
  QString connection_name_;
  QDBusConnection bus_;
  QString owner_, device_;
  Completion completion_;
  QTimer timeout_;
  std::unique_ptr<QDBusServiceWatcher> service_watcher_;
  bool claimed_ = false, started_ = false, finished_ = false;
};
}  // namespace
std::unique_ptr<Authorization> make_authorization(bool simulate) {
  if (simulate) return make_simulated_authorization();
  return std::make_unique<FprintdVerifier>();
}
}  // namespace fnox::portable
#include "authorization_linux.moc"
