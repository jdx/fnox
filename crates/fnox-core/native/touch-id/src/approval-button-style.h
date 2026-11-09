#ifndef FNOX_APPROVAL_BUTTON_STYLE_H
#define FNOX_APPROVAL_BUTTON_STYLE_H

#import <AppKit/AppKit.h>
#include "theme.generated.h"

namespace fnox {

inline BOOL ApprovalUsesOutline(NSAppearance* appearance) {
  return [[appearance
      bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]]
      isEqualToString:NSAppearanceNameAqua];
}

inline NSColor* ThemeColor(const uint32_t (&colors)[2], NSAppearance* appearance) {
  const BOOL dark = [[appearance
      bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]]
      isEqualToString:NSAppearanceNameDarkAqua];
  const uint32_t c = colors[dark ? 1 : 0];
  return [NSColor colorWithSRGBRed:((c >> 16) & 255) / 255.0
                             green:((c >> 8) & 255) / 255.0
                              blue:(c & 255) / 255.0
                             alpha:1];
}
inline NSColor* ApprovalRestingFill(NSAppearance* appearance) {
  return ThemeColor(kThemeResting, appearance);
}
inline NSColor* ApprovalCancelFill(NSAppearance* appearance) {
  return ApprovalRestingFill(appearance);
}
inline NSColor* ApprovalCancelTitleColor(NSAppearance* appearance) {
  return ThemeColor(kThemeCancelText, appearance);
}

inline constexpr CGFloat kApprovalButtonBorderWidth = 1;
inline constexpr CGFloat kApprovalButtonFocusWidth = 1.25;
inline constexpr CGFloat kApprovalButtonCornerRadius = 10;

inline NSBezierPath* ApprovalButtonOutline(NSRect bounds, CGFloat inset) {
  const NSRect frame = NSInsetRect(bounds, inset, inset);
  const CGFloat radius =
      MAX(0, MIN(kApprovalButtonCornerRadius - inset, MIN(NSWidth(frame), NSHeight(frame)) / 2));
  return [NSBezierPath bezierPathWithRoundedRect:frame xRadius:radius yRadius:radius];
}

inline NSBezierPath* ApprovalButtonBodyPath(NSRect bounds) {
  return ApprovalButtonOutline(bounds, kApprovalButtonFocusWidth);
}

inline void StrokeApprovalButton(NSRect bounds, NSColor* color) {
  [color setStroke];
  NSBezierPath* outline =
      ApprovalButtonOutline(bounds, kApprovalButtonFocusWidth + kApprovalButtonBorderWidth / 2);
  outline.lineWidth = kApprovalButtonBorderWidth;
  [outline stroke];
}

inline NSBezierPath* ApprovalButtonFocusPath(NSRect bounds) {
  NSBezierPath* path = ApprovalButtonOutline(bounds, kApprovalButtonFocusWidth / 2);
  path.lineWidth = kApprovalButtonFocusWidth;
  return path;
}

}  // namespace fnox

#endif
