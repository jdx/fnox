#pragma once

#include <functional>
#include <memory>
#include <string>

namespace fnox::portable {

enum class Result { Verified, Denied, Unavailable, Error };

class Authorization {
 public:
  using Completion = std::function<void(Result, std::string)>;
  virtual ~Authorization() = default;
  virtual void start(Completion completion) = 0;
  virtual void cancel() = 0;
};

std::unique_ptr<Authorization> make_authorization(bool simulate);
std::unique_ptr<Authorization> make_simulated_authorization();

}  // namespace fnox::portable
