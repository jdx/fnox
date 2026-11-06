#pragma once
#import <Foundation/Foundation.h>

namespace fnox {
// System verification is opt-in and never reads credentials. Screenshot mode
// only changes presentation; it cannot change the authorization backend.
inline bool IsSystemVerification() {
  static const bool enabled =
      [NSProcessInfo.processInfo.environment[@"FNOX_PREVIEW_AUTH"] isEqualToString:@"system"];
  return enabled;
}

inline bool IsScreenshotMode() {
  static const bool enabled =
      [NSProcessInfo.processInfo.environment[@"FNOX_PREVIEW_MODE"] isEqualToString:@"screenshot"];
  return enabled;
}
}  // namespace fnox
