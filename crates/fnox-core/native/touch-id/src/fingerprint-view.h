#import <AppKit/AppKit.h>

double FnoxFingerprintApprovalDuration(BOOL reduceMotion);

@interface FnoxFingerprintView : NSView
- (void)animateNudge;
- (void)animateSuccess;
@end
