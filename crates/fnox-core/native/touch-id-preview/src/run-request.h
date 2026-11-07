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
  std::string invoking_command;
  std::string project_directory;
  std::string credential_source;
  bool credential_access = false;
  bool system_verification = false;
};
}  // namespace fnox
