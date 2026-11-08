#include <QTimer>
#include <memory>

#include "authorization.h"

namespace fnox::portable {
namespace {
class Simulated final : public Authorization {
  struct Pending {
    bool cancelled = false;
    Completion completion;
  };

 public:
  ~Simulated() override { cancel(); }
  void start(Completion completion) override {
    pending_ = std::make_shared<Pending>();
    pending_->completion = std::move(completion);
    auto pending = pending_;
    QTimer::singleShot(120, [pending] {
      if (!pending->cancelled && pending->completion)
        pending->completion(Result::Verified, {});
    });
  }
  void cancel() override {
    if (pending_) {
      pending_->cancelled = true;
      pending_->completion = {};
    }
  }

 private:
  std::shared_ptr<Pending> pending_;
};
}  // namespace
std::unique_ptr<Authorization> make_simulated_authorization() {
  return std::make_unique<Simulated>();
}
}  // namespace fnox::portable
