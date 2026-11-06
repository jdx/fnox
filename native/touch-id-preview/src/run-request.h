#pragma once
#include <string>
#include <vector>

namespace fnox {
struct CredentialRequest {
  std::string binding_id;
  std::string identifier;
};
struct PreviewPath {
  std::string canonical_path;
};
struct RunOptions {
  std::vector<CredentialRequest> credentials;
  PreviewPath executable;
};
}  // namespace fnox
