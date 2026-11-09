#ifndef FNOX_APPROVAL_PROMPT_H
#define FNOX_APPROVAL_PROMPT_H

#include <string_view>

#include "authorization.h"
#include "run-request.h"

namespace fnox {

bool ShowApprovalPrompt(const RunOptions& options, std::string_view request_id,
                        TouchIdAuthorization& context, std::string_view reason,
                        TouchIdError& error);

}  // namespace fnox

#endif
