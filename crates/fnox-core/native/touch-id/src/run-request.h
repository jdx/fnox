#pragma once
#include <string>
#include <vector>

namespace fnox {
struct CredentialRequest {
  std::string binding_id;
  std::string identifier;
};
struct ExecutablePath {
  std::string canonical_path;
};
struct RunOptions {
  std::vector<CredentialRequest> credentials;
  ExecutablePath executable;
  std::string invoking_command;
  std::string project_directory;
  std::string credential_source;
  std::string credential_scope;
  bool credential_access = false;
  bool system_verification = false;
};
}  // namespace fnox
