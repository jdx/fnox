#include "authorization.h"

namespace fnox::portable {
namespace {
class Unavailable final : public Authorization {
 public:
  void start(Completion completion) override {
    completion(
        Result::Unavailable,
        "System verification is unavailable in the portable macOS preview.");
  }
  void cancel() override {}
};
}  // namespace
std::unique_ptr<Authorization> make_authorization(bool simulate) {
  if (simulate) return make_simulated_authorization();
  return std::make_unique<Unavailable>();
}
}  // namespace fnox::portable
