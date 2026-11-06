#import <AppKit/AppKit.h>
#include <iostream>
#include "approval-button-style.h"
#include "approval-prompt.h"
#include "preview-mode.h"
#include "detail-copy-icons.generated.h"

namespace {
constexpr CGFloat kPreviewLogoSize = 24;
constexpr CGFloat kPreviewLabelSize = 9;
constexpr CGFloat kDarkRibbonBorderWidth = 2;
constexpr CGFloat kLightRibbonBorderWidth = 1;
constexpr CGFloat kLogoShadowRadius = 1.5;
}  // namespace

@interface FnoxPreviewRibbon : NSView
@property(strong) NSImage* shield;
@end

@implementation FnoxPreviewRibbon
- (instancetype)initWithFrame:(NSRect)frame {
  self = [super initWithFrame:frame];
  if (self) {
    self.shield = [[NSImage alloc] initWithData:
        [NSData dataWithBytes:kPreviewLogoSvg length:sizeof(kPreviewLogoSvg)]];
    if (!self.shield) {
      [NSException raise:NSInternalInconsistencyException
                  format:@"Preview shield could not be decoded"];
    }
  }
  return self;
}
- (NSView*)hitTest:(NSPoint)point {
  (void)point;
  return nil;
}
- (void)drawRect:(NSRect)dirtyRect {
  (void)dirtyRect;
  const BOOL dark = [[self.effectiveAppearance
      bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]]
      isEqualToString:NSAppearanceNameDarkAqua];
  NSColor* ribbonColor = fnox::ThemeColor(fnox::kThemeRibbon, self.effectiveAppearance);
  NSColor* ribbonInk = fnox::ThemeColor(fnox::kThemePressed, self.effectiveAppearance);
  NSColor* ribbonEdge = fnox::ThemeColor(fnox::kThemeBorder, self.effectiveAppearance);
  [NSGraphicsContext saveGraphicsState];
  NSRectClip(self.bounds);
  NSAffineTransform* transform = [NSAffineTransform transform];
  [transform translateXBy:30 yBy:50];
  [transform rotateByDegrees:45];
  [transform concat];
  [NSGraphicsContext saveGraphicsState];
  NSShadow* ribbonShadow = [NSShadow new];
  ribbonShadow.shadowColor = [NSColor colorWithWhite:0 alpha:0.25];
  ribbonShadow.shadowOffset = NSMakeSize(0, -1);
  ribbonShadow.shadowBlurRadius = 4;
  if (dark) [ribbonShadow set];
  [ribbonColor setFill];
  NSRectFill(NSMakeRect(-75, -10, 150, 20));
  [NSGraphicsContext restoreGraphicsState];
  [ribbonEdge setStroke];
  NSBezierPath* border = [NSBezierPath bezierPathWithRect:NSMakeRect(-74.5, -9.5, 149, 19)];
  border.lineWidth = dark ? kDarkRibbonBorderWidth : kLightRibbonBorderWidth;
  [border stroke];
  NSShadow* textShadow = [NSShadow new];
  textShadow.shadowColor = [NSColor colorWithWhite:0 alpha:dark ? 0.35 : 0];
  textShadow.shadowOffset = NSMakeSize(0, -1);
  textShadow.shadowBlurRadius = 1;
  NSAttributedString* label = [[NSAttributedString alloc]
      initWithString:@"Preview"
          attributes:@{
            NSFontAttributeName : [NSFont boldSystemFontOfSize:kPreviewLabelSize],
            NSForegroundColorAttributeName : ribbonInk,
            NSKernAttributeName : @0.48,
            NSShadowAttributeName : textShadow,
          }];
  const NSSize labelSize = label.size;
  const CGFloat shieldSize = kPreviewLogoSize;
  const CGFloat groupWidth = shieldSize + 4 + labelSize.width;
  const NSRect shieldRect = NSMakeRect(-groupWidth / 2, -shieldSize / 2, shieldSize, shieldSize);
  [NSGraphicsContext saveGraphicsState];
  if (dark) {
    NSShadow* logoShadow = [NSShadow new];
    logoShadow.shadowColor = [NSColor colorWithSRGBRed:10.0 / 255
                                                 green:14.0 / 255
                                                  blue:26.0 / 255
                                                 alpha:0.65];
    logoShadow.shadowOffset = NSMakeSize(0, -1);
    logoShadow.shadowBlurRadius = kLogoShadowRadius;
    [logoShadow set];
  }
  [self.shield drawInRect:shieldRect];
  [NSGraphicsContext restoreGraphicsState];
  [label drawAtPoint:NSMakePoint(-groupWidth / 2 + shieldSize + 4, -labelSize.height / 2)];
  [NSGraphicsContext restoreGraphicsState];
}
@end


int main() {
  @autoreleasepool {
    NSString* auth = NSProcessInfo.processInfo.environment[@"FNOX_PREVIEW_AUTH"];
    if (auth != nil && ![auth isEqualToString:@"system"] && ![auth isEqualToString:@"simulate"]) {
      std::cerr << "FNOX_PREVIEW_AUTH must be simulate or system\n";
      return 2;
    }
    [NSApplication sharedApplication];
    NSString* requestedAppearance =
        NSProcessInfo.processInfo.environment[@"FNOX_PREVIEW_APPEARANCE"];
    if ([requestedAppearance isEqualToString:@"dark"]) {
      NSApp.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    } else if ([requestedAppearance isEqualToString:@"light"]) {
      NSApp.appearance = [NSAppearance appearanceNamed:NSAppearanceNameAqua];
    }
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp finishLaunching];
    [NSApp activate];
    id observer = [NSNotificationCenter.defaultCenter
        addObserverForName:NSWindowDidBecomeKeyNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification* notification) {
                  if (fnox::IsScreenshotMode()) return;
                  NSWindow* window = notification.object;
                  NSView* content = window.contentView;
                  for (NSView* child in content.subviews) {
                    if ([child.identifier isEqualToString:@"FnoxPreviewRibbon"]) return;
                  }
                  FnoxPreviewRibbon* ribbon = [[FnoxPreviewRibbon alloc]
                      initWithFrame:NSMakeRect(0, content.bounds.size.height - 80, 80, 80)];
                  ribbon.identifier = @"FnoxPreviewRibbon";
                  ribbon.autoresizingMask = NSViewMinYMargin;
                  ribbon.accessibilityElement = YES;
                  ribbon.accessibilityRole = NSAccessibilityStaticTextRole;
                  ribbon.accessibilityLabel = fnox::IsSystemVerification()
                      ? @"Verification demo. macOS owns Touch ID. No credential access."
                      : @"Preview. Press Shift-Return to simulate Touch ID success. No credential access.";
                  [content addSubview:ribbon positioned:NSWindowAbove relativeTo:nil];
                }];
    fnox::RunOptions options;
    options.credentials.push_back({"project:keel/GITHUB_TOKEN", "GITHUB_TOKEN"});
    options.executable.canonical_path = "/usr/local/bin/claude";
    fnox::PreviewAuthorization context;
    fnox::PreviewError error;
    const bool approved = fnox::ShowApprovalPrompt(options, std::string(64, 'a'), context,
                                                   "Fnox credential proxy preview", error);
    [NSNotificationCenter.defaultCenter removeObserver:observer];
    if (!approved) {
      if (error.status != fnox::PreviewStatus::kCancelled) {
        std::cerr << "fnox preview failed: " << error.detail << '\n';
      }
      return 1;
    }
  }
  return 0;
}
