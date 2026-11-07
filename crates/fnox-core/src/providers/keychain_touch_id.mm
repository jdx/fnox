#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#include "approval-prompt.h"
#include "preview-authorization.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static char *fnox_copy_error(NSString *message) {
  const char *utf8 = message.UTF8String ?: "Touch ID Keychain operation failed";
  return strdup(utf8);
}

static NSDictionary *fnox_item_query(NSString *service, NSString *account,
                                     LAContext *context,
                                     NSString *localized_reason) {
  context.localizedReason = localized_reason;
  NSMutableDictionary *query = [@{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : service,
    (__bridge id)kSecAttrAccount : account,
    (__bridge id)kSecUseAuthenticationContext : context,
    (__bridge id)kSecUseDataProtectionKeychain : @YES,
  } mutableCopy];
  NSString *access_group = NSBundle.mainBundle.infoDictionary[@"FNOXKeychainAccessGroup"];
  if (access_group.length > 0) query[(__bridge id)kSecAttrAccessGroup] = access_group;
  return query;
}

extern "C" {

int fnox_touch_id_validate_helper(const char *path_utf8, char **error_out) {
  @autoreleasepool {
    NSString *path = path_utf8 ? [NSString stringWithUTF8String:path_utf8] : nil;
    if (!path || !error_out) {
      if (error_out) *error_out = fnox_copy_error(@"Invalid Fnox Touch ID helper path");
      return (int)errSecParam;
    }

    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(
        (__bridge CFURLRef)[NSURL fileURLWithPath:path], kSecCSDefaultFlags, &code);
    if (status != errSecSuccess) {
      *error_out = fnox_copy_error(@"The Fnox Touch ID helper has no valid code signature");
      return (int)status;
    }

    SecRequirementRef requirement = NULL;
    status = SecRequirementCreateWithString(CFSTR("anchor apple generic"),
                                             kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess) {
      status = SecStaticCodeCheckValidity(
          code, kSecCSStrictValidate | kSecCSCheckAllArchitectures |
                    kSecCSCheckNestedCode,
          requirement);
    }
    if (requirement) CFRelease(requirement);
    if (status != errSecSuccess) {
      CFRelease(code);
      *error_out = fnox_copy_error(@"The Fnox Touch ID helper must have a valid Apple Developer ID signature");
      return (int)status;
    }

    CFDictionaryRef signing_info_ref = NULL;
    status = SecCodeCopySigningInformation((SecCodeRef)code, kSecCSSigningInformation,
                                            &signing_info_ref);
    CFRelease(code);
    if (status != errSecSuccess || !signing_info_ref) {
      if (signing_info_ref) CFRelease(signing_info_ref);
      *error_out = fnox_copy_error(@"Unable to read the Fnox Touch ID helper's signed entitlements");
      return status != errSecSuccess ? (int)status : (int)errSecAuthFailed;
    }

    NSDictionary *signing_info = CFBridgingRelease(signing_info_ref);
    NSDictionary *entitlements = signing_info[(__bridge id)kSecCodeInfoEntitlementsDict];
    NSString *team = signing_info[(__bridge id)kSecCodeInfoTeamIdentifier];
    NSString *bundle_path = [[[path stringByDeletingLastPathComponent]
        stringByDeletingLastPathComponent] stringByDeletingLastPathComponent];
    NSDictionary *bundle_info = [NSBundle bundleWithPath:bundle_path].infoDictionary;
    NSString *bundle_id = bundle_info[@"CFBundleIdentifier"];
    NSString *access_group = bundle_info[@"FNOXKeychainAccessGroup"];
    NSString *application_id = entitlements[@"application-identifier"] ?:
        entitlements[@"com.apple.application-identifier"];
    NSArray *access_groups = entitlements[@"keychain-access-groups"];
    NSString *expected_application_id = team && bundle_id
        ? [NSString stringWithFormat:@"%@.%@", team, bundle_id]
        : nil;
    BOOL valid_entitlements = team.length > 0 && bundle_id.length > 0 &&
        access_group.length > 0 && [access_group hasPrefix:[team stringByAppendingString:@"."]] &&
        [application_id isEqualToString:expected_application_id] &&
        [access_groups isKindOfClass:[NSArray class]] &&
        [access_groups containsObject:access_group];
    if (!valid_entitlements) {
      *error_out = fnox_copy_error(@"The Fnox Touch ID helper signature does not authorize its declared Keychain access group");
      return (int)errSecAuthFailed;
    }

    *error_out = NULL;
    return (int)errSecSuccess;
  }
}

int fnox_touch_id_get(const char *service_utf8, const char *account_utf8,
                      const char *reason_utf8, const char *executable_utf8,
                      const char *project_utf8, const char *command_utf8,
                      char **value_out,
                      size_t *length_out, char **error_out) {
  @autoreleasepool {
    NSString *service = [NSString stringWithUTF8String:service_utf8];
    NSString *account = [NSString stringWithUTF8String:account_utf8];
    NSString *reason = [NSString stringWithUTF8String:reason_utf8];
    NSString *executable = [NSString stringWithUTF8String:executable_utf8];
    NSString *project = [NSString stringWithUTF8String:project_utf8];
    NSString *command = [NSString stringWithUTF8String:command_utf8];
    if (!service || !account || !reason || !executable || !project || !command ||
        !value_out || !length_out || !error_out) {
      if (error_out) *error_out = fnox_copy_error(@"Invalid Touch ID Keychain request");
      return (int)errSecParam;
    }

    fnox::RunOptions options;
    options.credentials.push_back({"keychain:" + std::string(account_utf8), std::string(account_utf8)});
    options.executable.canonical_path = executable.UTF8String ?: "";
    options.invoking_command = command.UTF8String ?: "";
    options.project_directory = project.UTF8String ?: "";
    options.credential_source = "macOS Keychain · Touch ID protected";
    options.credential_access = true;
    options.system_verification = true;
    LAContext *context = nil;
    fnox::PreviewAuthorization authorization(true);
    fnox::PreviewError authorization_error;
    NSString *request_id = NSUUID.UUID.UUIDString;
    if (!fnox::ShowApprovalPrompt(options, request_id.UTF8String ?: "", authorization,
                                  std::string_view(reason_utf8), authorization_error)) {
      *error_out = fnox_copy_error([NSString stringWithUTF8String:authorization_error.detail.c_str()] ?: @"Touch ID authorization failed");
      return authorization_error.os_status != 0 ? authorization_error.os_status : (int)errSecAuthFailed;
    }
    context = (__bridge LAContext *)authorization.AuthenticationContext();

    CFTypeRef result = NULL;
    NSMutableDictionary *mutable_query =
        [fnox_item_query(service, account, context, reason) mutableCopy];
    mutable_query[(__bridge id)kSecReturnData] = @YES;
    mutable_query[(__bridge id)kSecReturnAttributes] = @YES;
    mutable_query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)mutable_query, &result);
    if (status != errSecSuccess) {
      *error_out = fnox_copy_error([NSString stringWithFormat:@"Keychain read failed (status %d)", (int)status]);
      return (int)status;
    }

    NSDictionary *item = CFBridgingRelease(result);
    id access_control = item[(__bridge id)kSecAttrAccessControl];
    if (!access_control || CFGetTypeID((__bridge CFTypeRef)access_control) !=
                               SecAccessControlGetTypeID()) {
      *error_out = fnox_copy_error(@"The matching Keychain item is not protected by biometric access control");
      return (int)errSecAuthFailed;
    }
    NSData *data = item[(__bridge id)kSecValueData];
    if (![data isKindOfClass:[NSData class]]) {
      *error_out = fnox_copy_error(@"Keychain did not return the protected secret data");
      return (int)errSecDecode;
    }
    char *copy = static_cast<char *>(malloc(data.length + 1));
    if (!copy) {
      *error_out = fnox_copy_error(@"Unable to allocate Keychain result");
      return (int)errSecAllocate;
    }
    memcpy(copy, data.bytes, data.length);
    copy[data.length] = '\0';
    *value_out = copy;
    *length_out = data.length;
    *error_out = NULL;
    return (int)errSecSuccess;
  }
}

int fnox_touch_id_set(const char *service_utf8, const char *account_utf8,
                      const uint8_t *value_bytes, size_t value_length,
                      const char *reason_utf8,
                      char **error_out) {
  @autoreleasepool {
    NSString *service = [NSString stringWithUTF8String:service_utf8];
    NSString *account = [NSString stringWithUTF8String:account_utf8];
    NSString *reason = [NSString stringWithUTF8String:reason_utf8];
    if (!service || !account || !reason || !error_out || (!value_bytes && value_length)) {
      if (error_out) *error_out = fnox_copy_error(@"Invalid Touch ID Keychain request");
      return (int)errSecParam;
    }

    NSData *data = [NSData dataWithBytes:value_bytes length:value_length];
    CFErrorRef access_error = NULL;
    SecAccessControlRef access_control = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet, &access_error);
    if (!access_control) {
      NSError *access_failure = CFBridgingRelease(access_error);
      NSString *message = access_failure.localizedDescription ?: @"Unable to create biometric Keychain policy";
      *error_out = fnox_copy_error(message);
      return (int)errSecParam;
    }

    NSMutableDictionary *attributes = [@{
      (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService : service,
      (__bridge id)kSecAttrAccount : account,
      (__bridge id)kSecValueData : data,
      (__bridge id)kSecAttrAccessControl : CFBridgingRelease(access_control),
      (__bridge id)kSecUseDataProtectionKeychain : @YES,
    } mutableCopy];
    NSString *access_group = NSBundle.mainBundle.infoDictionary[@"FNOXKeychainAccessGroup"];
    if (access_group.length > 0) attributes[(__bridge id)kSecAttrAccessGroup] = access_group;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
    if (status == errSecDuplicateItem) {
      NSMutableDictionary *query = [@{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : service,
        (__bridge id)kSecAttrAccount : account,
        (__bridge id)kSecReturnAttributes : @YES,
        (__bridge id)kSecUseDataProtectionKeychain : @YES,
      } mutableCopy];
      NSString *access_group = NSBundle.mainBundle.infoDictionary[@"FNOXKeychainAccessGroup"];
      if (access_group.length > 0) query[(__bridge id)kSecAttrAccessGroup] = access_group;
      CFTypeRef existing_result = NULL;
      status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &existing_result);
      if (status == errSecSuccess) {
        NSDictionary *existing = CFBridgingRelease(existing_result);
        id existing_access_control = existing[(__bridge id)kSecAttrAccessControl];
        if (!existing_access_control ||
            CFGetTypeID((__bridge CFTypeRef)existing_access_control) !=
                SecAccessControlGetTypeID()) {
          *error_out = fnox_copy_error(@"Refusing to update a Keychain item without biometric access control; remove it and write it again");
          return (int)errSecAuthFailed;
        }
        LAContext *context = [LAContext new];
        context.localizedFallbackTitle = @"";
        NSError *availability_error = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                  error:&availability_error]) {
          *error_out = fnox_copy_error(availability_error.localizedDescription ?: @"Touch ID is unavailable");
          return (int)errSecNotAvailable;
        }
        NSDictionary *update_query = fnox_item_query(service, account, context, reason);
        status = SecItemUpdate((__bridge CFDictionaryRef)update_query,
                               (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData : data});
      }
    }
    if (status != errSecSuccess) {
      *error_out = fnox_copy_error([NSString stringWithFormat:@"Keychain write failed (status %d)", (int)status]);
    } else {
      *error_out = NULL;
    }
    return (int)status;
  }
}

int fnox_touch_id_delete(const char *service_utf8, const char *account_utf8,
                         char **error_out) {
  @autoreleasepool {
    NSString *service = [NSString stringWithUTF8String:service_utf8];
    NSString *account = [NSString stringWithUTF8String:account_utf8];
    if (!service || !account || !error_out) {
      if (error_out) *error_out = fnox_copy_error(@"Invalid Touch ID Keychain cleanup request");
      return (int)errSecParam;
    }
    NSDictionary *query = @{
      (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService : service,
      (__bridge id)kSecAttrAccount : account,
      (__bridge id)kSecUseDataProtectionKeychain : @YES,
    };
    NSMutableDictionary *mutable_query = [query mutableCopy];
    NSString *access_group = NSBundle.mainBundle.infoDictionary[@"FNOXKeychainAccessGroup"];
    if (access_group.length > 0) mutable_query[(__bridge id)kSecAttrAccessGroup] = access_group;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)mutable_query);
    if (status == errSecSuccess || status == errSecItemNotFound) {
      *error_out = NULL;
      return (int)errSecSuccess;
    }
    *error_out = fnox_copy_error([NSString stringWithFormat:@"Keychain cleanup failed (status %d)", (int)status]);
    return (int)status;
  }
}

void fnox_touch_id_free(void *pointer) { free(pointer); }

}  // extern "C"
