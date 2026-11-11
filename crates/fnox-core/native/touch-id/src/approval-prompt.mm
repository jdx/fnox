#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import "approval-button-style.h"
#import "approval-presentation.h"
#include "detail-copy-icons.generated.h"
#import "fingerprint-view.h"

#include "approval-prompt.h"
#include "approval-readiness.h"
#include "preview-mode.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <string>
#include <vector>

// NSGlassEffectView only exists in the macOS 26 SDK. Older SDKs (such as the
// one on CI runners) cannot compile the glass surface, so the panel keeps its
// standard opaque content view there.
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
#define FNOX_HAS_GLASS_SDK 1
#else
#define FNOX_HAS_GLASS_SDK 0
#endif

extern bool FnoxPreviewAcceptTouchId();

constexpr CGFloat kFingerprintClipBottomInset = 18;
constexpr CGFloat kExpandedFooterHeight = 72;
constexpr CGFloat kExpandedRowsFooterGap = 12;
constexpr CGFloat kExpandedRowsHeadingGap = 12;
constexpr CGFloat kExpandedHeadingHeight = 24;
constexpr CGFloat kExpandedTopInset = 20;
constexpr CFTimeInterval kTextShimmerLeadIn = 0.8;
constexpr CFTimeInterval kTextShimmerSweep = 1.8;
constexpr CFTimeInterval kTextShimmerRest = 5.2;
constexpr CFTimeInterval kTextShimmerCycle = kTextShimmerSweep + kTextShimmerRest;
constexpr auto kApprovalReadinessTimeout = std::chrono::seconds(5);

NSColor* FnoxBrandColor() {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor*(NSAppearance* appearance) {
                  return fnox::ThemeColor(fnox::kThemeAccent, appearance);
                }];
}

NSColor* FnoxButtonTitleColor() {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor*(NSAppearance* appearance) {
                  return fnox::ThemeColor(fnox::kThemeAccent, appearance);
                }];
}

NSColor* FnoxCopyIconColor() {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor*(NSAppearance* appearance) {
                  return fnox::ThemeColor(fnox::kThemeHighlight, appearance);
                }];
}

NSColor* FnoxHeadingColor() {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor*(NSAppearance* appearance) {
                  return fnox::ThemeColor(fnox::kThemeHeading, appearance);
                }];
}

NSColor* FnoxInstructionColor() {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor*(NSAppearance* appearance) {
                  return fnox::ThemeColor(fnox::kThemeAccent, appearance);
                }];
}

NSColor* FnoxShimmerHighlightColor() {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor*(NSAppearance* appearance) {
                  return fnox::ThemeColor(fnox::kThemeShimmer, appearance);
                }];
}

NSAppearance* AppearanceForView(NSView* view) {
  return view.effectiveAppearance != nil ? view.effectiveAppearance : NSApp.effectiveAppearance;
}

NSColor* ColorForAppearance(NSColor* color, NSAppearance* appearance) {
  __block NSColor* resolved = nil;
  [appearance performAsCurrentDrawingAppearance:^{
    resolved = [color colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
  }];
  return resolved != nil ? resolved : color;
}

@interface FnoxApprovalPanel : NSPanel
@property(nonatomic) BOOL keyboardFocusVisible;
@property(nonatomic, strong) NSView* approvalContent;
@end

@implementation FnoxApprovalPanel
@end

#if FNOX_HAS_GLASS_SDK
// The glass view subclass is built at runtime. A static `@interface ... :
// NSGlassEffectView` makes the binary link the superclass symbol at load time,
// so dyld aborts before main on macOS releases that predate it.
static void FnoxGlassUpdateSurface(NSGlassEffectView* self, SEL) API_AVAILABLE(macos(26.0));
static void FnoxGlassUpdateSurface(NSGlassEffectView* self, SEL) {
  NSAppearanceName appearance = [self.effectiveAppearance
      bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]];
  const BOOL lightFrost = self.style == NSGlassEffectViewStyleRegular &&
                          ![appearance isEqualToString:NSAppearanceNameDarkAqua];
  const BOOL regularGlass = self.style == NSGlassEffectViewStyleRegular;
  const BOOL reduceTransparency =
      NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceTransparency;
  self.contentView.wantsLayer = YES;
  self.contentView.layer.cornerRadius = self.cornerRadius;
  self.contentView.layer.masksToBounds = YES;
  NSColor* tint = NSColor.clearColor;
  if (lightFrost) {
    tint = [NSColor colorWithSRGBRed:0.98 green:0.97 blue:0.95 alpha:reduceTransparency ? 1 : 0.24];
  } else if (regularGlass) {
    tint = [NSColor colorWithSRGBRed:10.0 / 255
                               green:14.0 / 255
                                blue:26.0 / 255
                               alpha:reduceTransparency ? 1 : 0.88];
  }
  self.contentView.layer.backgroundColor = tint.CGColor;
}

static Class FnoxGlassSuperclass(id self) { return class_getSuperclass(object_getClass(self)); }

static void FnoxGlassDidChangeAppearance(NSGlassEffectView* self, SEL cmd)
    API_AVAILABLE(macos(26.0));
static void FnoxGlassDidChangeAppearance(NSGlassEffectView* self, SEL cmd) {
  struct objc_super super_ = {(__bridge void*)self, FnoxGlassSuperclass(self)};
  ((void (*)(struct objc_super*, SEL))objc_msgSendSuper)(&super_, cmd);
  FnoxGlassUpdateSurface(self, nullptr);
}

static void FnoxGlassSetStyle(NSGlassEffectView* self, SEL cmd, NSGlassEffectViewStyle style)
    API_AVAILABLE(macos(26.0));
static void FnoxGlassSetStyle(NSGlassEffectView* self, SEL cmd, NSGlassEffectViewStyle style) {
  struct objc_super super_ = {(__bridge void*)self, FnoxGlassSuperclass(self)};
  ((void (*)(struct objc_super*, SEL, NSGlassEffectViewStyle))objc_msgSendSuper)(&super_, cmd,
                                                                                  style);
  FnoxGlassUpdateSurface(self, nullptr);
}

// Returns Nil when the running system has no NSGlassEffectView (before macOS 26).
static Class FnoxApprovalGlassViewClass() {
  static Class glassClass = Nil;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    Class base = NSClassFromString(@"NSGlassEffectView");
    if (base == Nil) return;
    Class cls = objc_allocateClassPair(base, "FnoxApprovalGlassView", 0);
    if (cls == Nil) return;
    class_addMethod(cls, @selector(updateSurface), (IMP)FnoxGlassUpdateSurface, "v@:");
    class_addMethod(cls, @selector(viewDidChangeEffectiveAppearance),
                    (IMP)FnoxGlassDidChangeAppearance, "v@:");
    class_addMethod(cls, @selector(setStyle:), (IMP)FnoxGlassSetStyle, "v@:q");
    objc_registerClassPair(cls);
    glassClass = cls;
  });
  return glassClass;
}
#endif

void DrawFnoxFocusRing(NSView* view) {
  if (view.window == nil || view.window.firstResponder != view ||
      ![view.window isKindOfClass:[FnoxApprovalPanel class]] ||
      !((FnoxApprovalPanel*)view.window).keyboardFocusVisible)
    return;
  const BOOL bordered = [view isKindOfClass:[NSButton class]] && ((NSButton*)view).bordered;
  NSBezierPath* ring =
      bordered ? [NSBezierPath bezierPathWithRoundedRect:NSInsetRect(view.bounds, 0.5, 2.5)
                                                 xRadius:6
                                                 yRadius:6]
               : fnox::ApprovalButtonFocusPath(view.bounds);
  ring.lineWidth = fnox::kApprovalButtonFocusWidth;
  [ColorForAppearance(FnoxBrandColor(), AppearanceForView(view)) setStroke];
  [ring stroke];
}

@interface FnoxDetailCopyButton : NSButton
@property(copy) NSString* payload;
@property(copy) NSString* detailName;
@property(strong) NSTimer* resetTimer;
- (void)copyDetail:(id)sender;
- (void)setCopied:(BOOL)copied;
@end

@interface FnoxPanelButton : NSButton
@property NSModalResponse response;
@property(nonatomic) BOOL showsLinkCursor;
@property(copy) void (^actionHandler)(void);
- (void)setEnabled:(BOOL)enabled;
- (void)setShowsLinkCursor:(BOOL)showsLinkCursor;
- (void)finishModal:(id)sender;
@end

@interface FnoxInstructionLabel : NSTextField
@property(copy) void (^actionHandler)(void);
@end

@implementation FnoxPanelButton
- (void)drawRect:(NSRect)dirtyRect {
  {
    NSColor* color = ColorForAppearance(
        self.highlighted ? FnoxHeadingColor() : FnoxButtonTitleColor(), self.effectiveAppearance);
    NSMutableAttributedString* title = [self.attributedTitle mutableCopy];
    [title addAttribute:NSForegroundColorAttributeName
                  value:color
                  range:NSMakeRange(0, title.length)];
    if (![self.attributedTitle isEqualToAttributedString:title]) {
      self.attributedTitle = title;
    }
    if (![self.contentTintColor isEqual:color]) self.contentTintColor = color;
  }
  [NSGraphicsContext saveGraphicsState];
  [fnox::ApprovalButtonBodyPath(self.bounds) addClip];
  if (self.bordered) {
    NSColor* fill = self.response == NSAlertFirstButtonReturn
                        ? fnox::ApprovalCancelFill(self.effectiveAppearance)
                        : fnox::ApprovalRestingFill(self.effectiveAppearance);
    const BOOL outlined = self.response == NSAlertFirstButtonReturn &&
                          fnox::ApprovalUsesOutline(self.effectiveAppearance);
    if (!outlined) {
      [fill setFill];
      [fnox::ApprovalButtonBodyPath(self.bounds) fill];
    }
    if (self.response == NSAlertFirstButtonReturn) {
      NSColor* titleColor = fnox::ApprovalCancelTitleColor(self.effectiveAppearance);
      if (self.highlighted) {
        titleColor = outlined ? ColorForAppearance(FnoxHeadingColor(), self.effectiveAppearance)
                              : fnox::ThemeColor(fnox::kThemePressed, self.effectiveAppearance);
      }
      NSMutableAttributedString* title = [self.attributedTitle mutableCopy];
      [title addAttribute:NSForegroundColorAttributeName
                    value:titleColor
                    range:NSMakeRange(0, title.length)];
      self.attributedTitle = title;
      self.contentTintColor = titleColor;
      if (outlined) {
        fnox::StrokeApprovalButton(self.bounds, titleColor);
      }
    }
    [self.cell drawInteriorWithFrame:self.bounds inView:self];
  } else {
    [super drawRect:dirtyRect];
  }
  [NSGraphicsContext restoreGraphicsState];
  DrawFnoxFocusRing(self);
}
- (BOOL)becomeFirstResponder {
  const BOOL becameFirstResponder = [super becomeFirstResponder];
  [self setNeedsDisplay:YES];
  return becameFirstResponder;
}
- (BOOL)resignFirstResponder {
  const BOOL resignedFirstResponder = [super resignFirstResponder];
  [self setNeedsDisplay:YES];
  return resignedFirstResponder;
}
- (void)setEnabled:(BOOL)enabled {
  [super setEnabled:enabled];
  if (self.window != nil) [self.window invalidateCursorRectsForView:self];
}
- (void)setShowsLinkCursor:(BOOL)showsLinkCursor {
  _showsLinkCursor = showsLinkCursor;
  if (self.window != nil) [self.window invalidateCursorRectsForView:self];
}
- (void)resetCursorRects {
  [super resetCursorRects];
  if (self.showsLinkCursor && self.enabled && !self.hidden) {
    [self addCursorRect:self.bounds cursor:NSCursor.pointingHandCursor];
  }
}
- (void)finishModal:(id)sender {
  (void)sender;
  if (self.actionHandler != nil) {
    self.actionHandler();
    return;
  }
  [NSApp stopModalWithCode:self.response];
}
@end

@implementation FnoxInstructionLabel
- (void)mouseDown:(NSEvent*)event {
  (void)event;
  if (self.actionHandler != nil) self.actionHandler();
}
@end

@implementation FnoxDetailCopyButton
- (void)drawRect:(NSRect)dirtyRect {
  (void)dirtyRect;
  [NSGraphicsContext saveGraphicsState];
  [fnox::ApprovalButtonBodyPath(self.bounds) addClip];
  if (fnox::ApprovalUsesOutline(self.effectiveAppearance)) {
    fnox::StrokeApprovalButton(
        self.bounds, ColorForAppearance(FnoxButtonTitleColor(), self.effectiveAppearance));
  } else {
    [fnox::ApprovalCancelFill(self.effectiveAppearance) setFill];
    [fnox::ApprovalButtonBodyPath(self.bounds) fill];
  }
  [self.cell drawInteriorWithFrame:self.bounds inView:self];
  [NSGraphicsContext restoreGraphicsState];
  DrawFnoxFocusRing(self);
}
- (BOOL)becomeFirstResponder {
  const BOOL becameFirstResponder = [super becomeFirstResponder];
  [self setNeedsDisplay:YES];
  return becameFirstResponder;
}
- (BOOL)resignFirstResponder {
  const BOOL resignedFirstResponder = [super resignFirstResponder];
  [self setNeedsDisplay:YES];
  return resignedFirstResponder;
}
- (void)setCopied:(BOOL)copied {
  NSString* title = copied ? @"\u2009Copied" : [@"\u2009" stringByAppendingString:self.detailName];
  self.attributedTitle =
      [[NSAttributedString alloc] initWithString:title
                                      attributes:@{
                                        NSFontAttributeName : self.font,
                                        NSForegroundColorAttributeName : FnoxButtonTitleColor(),
                                      }];
  const unsigned char* bytes = copied ? kDetailCheckIconSvg : kDetailCopyIconSvg;
  const NSUInteger length = copied ? sizeof(kDetailCheckIconSvg) : sizeof(kDetailCopyIconSvg);
  NSImage* icon = [[NSImage alloc] initWithData:[NSData dataWithBytes:bytes length:length]];
  self.image = [NSImage imageWithSize:icon.size
                              flipped:NO
                       drawingHandler:^BOOL(NSRect bounds) {
                         [icon drawInRect:bounds];
                         [FnoxCopyIconColor() setFill];
                         NSRectFillUsingOperation(bounds, NSCompositingOperationSourceIn);
                         return YES;
                       }];
  self.contentTintColor = FnoxCopyIconColor();
  self.toolTip = copied ? [@"Copied " stringByAppendingString:self.detailName]
                        : [@"Copy " stringByAppendingString:self.detailName];
  self.accessibilityLabel = self.toolTip;
}
- (void)copyDetail:(id)sender {
  (void)sender;
  if (self.payload == nil) {
    return;
  }
  NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
  [pasteboard clearContents];
  if (![pasteboard setString:self.payload forType:NSPasteboardTypeString]) return;
  [self.resetTimer invalidate];
  [self setCopied:YES];
  __weak FnoxDetailCopyButton* weakSelf = self;
  self.resetTimer = [NSTimer timerWithTimeInterval:1.2
                                           repeats:NO
                                             block:^(NSTimer* timer) {
                                               (void)timer;
                                               [weakSelf setCopied:NO];
                                               weakSelf.resetTimer = nil;
                                             }];
  [[NSRunLoop mainRunLoop] addTimer:self.resetTimer forMode:NSRunLoopCommonModes];
}
@end

@interface FnoxDetailRowsView : NSView
@end

@interface FnoxTextShimmer : NSObject
@property(nonatomic, weak) NSTextField* label;
@property(nonatomic, strong) NSTimer* timer;
@property(nonatomic, strong) NSColor* baseColor;
@property(nonatomic, strong) NSColor* highlightColor;
@property(nonatomic) CFTimeInterval startTime;
@property(nonatomic) BOOL highlightsVisible;
- (instancetype)initWithLabel:(NSTextField*)label;
- (void)setBaseColor:(NSColor*)baseColor highlightColor:(NSColor*)highlightColor;
- (void)setHighlightsVisible:(BOOL)visible;
- (void)setEnabled:(BOOL)enabled;
- (void)update;
@end

@implementation FnoxDetailRowsView
- (BOOL)isFlipped {
  return YES;
}
@end

@implementation FnoxTextShimmer
- (instancetype)initWithLabel:(NSTextField*)label {
  self = [super init];
  if (self == nil) return nil;
  self.label = label;
  self.baseColor = FnoxInstructionColor();
  self.highlightColor = FnoxShimmerHighlightColor();
  self.highlightsVisible = YES;
  self.label.textColor = self.baseColor;
  return self;
}
- (void)setBaseColor:(NSColor*)baseColor highlightColor:(NSColor*)highlightColor {
  self.baseColor = baseColor;
  self.highlightColor = highlightColor;
  self.label.textColor = ColorForAppearance(baseColor, AppearanceForView(self.label));
  if (self.timer != nil) [self update];
}
- (void)setHighlightsVisible:(BOOL)visible {
  _highlightsVisible = visible;
  if (self.timer != nil) [self update];
}
- (void)setEnabled:(BOOL)enabled {
  if (!enabled || NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion) {
    [self.timer invalidate];
    self.timer = nil;
    self.label.textColor = self.baseColor;
    [self.label setStringValue:self.label.stringValue];
    return;
  }
  if (self.timer != nil) {
    [self update];
    return;
  }
  // Keep this timeline alive through compact/details transitions. Re-enabling
  // an existing shimmer refreshes its current frame instead of restarting it.
  self.startTime = CACurrentMediaTime();
  __weak FnoxTextShimmer* weakSelf = self;
  self.timer = [NSTimer timerWithTimeInterval:1.0 / 30.0
                                      repeats:YES
                                        block:^(NSTimer* timer) {
                                          (void)timer;
                                          [weakSelf update];
                                        }];
  [[NSRunLoop mainRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];
  [self update];
}
- (void)update {
  if (self.label == nil || self.timer == nil) return;
  NSString* value = self.label.stringValue;
  if (value.length == 0) return;
  const CFTimeInterval elapsed = CACurrentMediaTime() - self.startTime;
  NSAppearance* appearance = AppearanceForView(self.label);
  NSColor* baseColor = ColorForAppearance(self.baseColor, appearance);
  NSColor* highlightColor = ColorForAppearance(self.highlightColor, appearance);
  const BOOL dark = [[appearance
      bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]]
      isEqualToString:NSAppearanceNameDarkAqua];
  if (!self.highlightsVisible) {
    self.label.textColor = baseColor;
    self.label.stringValue = value;
    return;
  }
  const CFTimeInterval phase =
      elapsed < kTextShimmerLeadIn ? -1 : fmod(elapsed - kTextShimmerLeadIn, kTextShimmerCycle);
  if (phase < 0 || phase >= kTextShimmerSweep) {
    self.label.textColor = baseColor;
    self.label.stringValue = value;
    return;
  }
  const CGFloat halfWidth = MAX(static_cast<CGFloat>(value.length) * 0.1, 3);
  const CGFloat progress = static_cast<CGFloat>(phase / kTextShimmerSweep);
  const CGFloat center =
      progress * (static_cast<CGFloat>(value.length) + 2 * halfWidth) - halfWidth;
  NSMutableAttributedString* text =
      [[NSMutableAttributedString alloc] initWithString:value
                                             attributes:@{NSFontAttributeName : self.label.font}];
  NSUInteger offset = 0;
  while (offset < value.length) {
    const NSRange range = [value rangeOfComposedCharacterSequenceAtIndex:offset];
    const CGFloat distance = fabs(static_cast<CGFloat>(offset) - center);
    const CGFloat ratio = MIN(distance / halfWidth, 1);
    const CGFloat intensity =
        (dark ? 0.45 : 1.0) * 0.5 * (1 + std::cos(3.14159265358979323846 * ratio));
    NSColor* color = [baseColor blendedColorWithFraction:intensity ofColor:highlightColor];
    [text addAttribute:NSForegroundColorAttributeName value:color range:range];
    offset = NSMaxRange(range);
  }
  NSMutableParagraphStyle* paragraph = [NSMutableParagraphStyle new];
  paragraph.alignment = self.label.alignment;
  [text addAttribute:NSParagraphStyleAttributeName
               value:paragraph
               range:NSMakeRange(0, text.length)];
  self.label.attributedStringValue = text;
}
@end

namespace fnox {
namespace {

NSView* ApprovalContent(NSPanel* panel) { return ((FnoxApprovalPanel*)panel).approvalContent; }

void InstallApprovalGlass(FnoxApprovalPanel* panel, CGFloat width, CGFloat height) {
  // Keep the panel's standard content view on systems without NSGlassEffectView.
  panel.approvalContent = panel.contentView;
#if FNOX_HAS_GLASS_SDK
  Class glassClass = FnoxApprovalGlassViewClass();
  if (glassClass == Nil) return;
  if (@available(macOS 26.0, *)) {
    panel.styleMask |= NSWindowStyleMaskFullSizeContentView;
    panel.opaque = NO;
    panel.backgroundColor = NSColor.clearColor;
    NSGlassEffectView* glass = [[glassClass alloc] initWithFrame:panel.contentView.bounds];
    glass.style = NSGlassEffectViewStyleRegular;
    glass.cornerRadius = 16;
    glass.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    NSView* container = [[NSView alloc] initWithFrame:glass.bounds];
    NSView* content = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, width, height)];
    content.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    [container addSubview:content];
    glass.contentView = container;
    panel.contentView = glass;
    panel.approvalContent = content;
    FnoxGlassUpdateSurface(glass, nullptr);
  }
#else
  (void)width;
  (void)height;
#endif
}

void SetApprovalGlassTransition(NSPanel* panel, BOOL transitioning) {
#if FNOX_HAS_GLASS_SDK
  Class glassClass = FnoxApprovalGlassViewClass();
  if (@available(macOS 26.0, *)) {
    if (glassClass == Nil || ![panel.contentView isKindOfClass:glassClass]) return;
    const BOOL reduceEffects =
        NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion ||
        NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceTransparency;
    const BOOL clear = transitioning && !reduceEffects;
    NSGlassEffectView* glass = (NSGlassEffectView*)panel.contentView;
    CALayer* surface = glass.contentView.layer;
    CALayer* visibleSurface = surface.presentationLayer;
    CGColorRef currentColor = (visibleSurface != nil ? visibleSurface : surface).backgroundColor;
    CABasicAnimation* fade = [CABasicAnimation animationWithKeyPath:@"backgroundColor"];
    fade.fromValue = (__bridge id)currentColor;
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    glass.style = clear ? NSGlassEffectViewStyleClear : NSGlassEffectViewStyleRegular;
    [CATransaction commit];
    [surface removeAnimationForKey:@"approvalGlassFade"];
    if (!reduceEffects) {
      fade.toValue = (__bridge id)surface.backgroundColor;
      fade.duration = 0.45;
      fade.timingFunction =
          [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
      [surface addAnimation:fade forKey:@"approvalGlassFade"];
    }
  }
#else
  (void)panel;
  (void)transitioning;
#endif
}

NSPanel* RequestPanel(CGFloat width, CGFloat height, NSString* title) {
  NSPanel* panel = [[FnoxApprovalPanel alloc] initWithContentRect:NSMakeRect(0, 0, width, height)
                                                        styleMask:NSWindowStyleMaskTitled
                                                          backing:NSBackingStoreBuffered
                                                            defer:NO];
  panel.titleVisibility = NSWindowTitleHidden;
  panel.titlebarAppearsTransparent = YES;
  panel.movableByWindowBackground = YES;
  panel.collectionBehavior = NSWindowCollectionBehaviorMoveToActiveSpace;
  panel.autorecalculatesKeyViewLoop = NO;
  InstallApprovalGlass((FnoxApprovalPanel*)panel, width, height);
  NSTextField* heading = [NSTextField wrappingLabelWithString:title];
  heading.identifier = @"RequestHeading";
  heading.frame = NSMakeRect(20, height - 60, width - 40, 40);
  heading.font = [NSFont boldSystemFontOfSize:14];
  heading.selectable = NO;
  heading.textColor = FnoxHeadingColor();
  heading.alignment = NSTextAlignmentCenter;
  heading.toolTip = title;
  [ApprovalContent(panel) addSubview:heading];
  return panel;
}

NSTextField* PanelHeading(NSPanel* panel) {
  for (NSView* view in ApprovalContent(panel).subviews) {
    if ([view.identifier isEqualToString:@"RequestHeading"]) {
      return (NSTextField*)view;
    }
  }
  return nil;
}

FnoxPanelButton* PanelButton(NSPanel* panel, NSString* title, NSRect frame,
                             NSModalResponse response) {
  FnoxPanelButton* button = [[FnoxPanelButton alloc] initWithFrame:frame];
  button.title = title;
  button.bezelStyle = NSBezelStyleRounded;
  button.focusRingType = NSFocusRingTypeNone;
  button.response = response;
  button.target = button;
  button.action = @selector(finishModal:);
  [ApprovalContent(panel) addSubview:button];
  return button;
}

void StyleBrandButtonTitle(NSButton* button, NSString* title) {
  NSFont* font = button.font != nil ? button.font : [NSFont systemFontOfSize:13];
  button.bordered = NO;
  ((NSButtonCell*)button.cell).highlightsBy = NSNoCellMask;
  button.contentTintColor = FnoxButtonTitleColor();
  button.attributedTitle =
      [[NSAttributedString alloc] initWithString:title
                                      attributes:@{
                                        NSFontAttributeName : font,
                                        NSForegroundColorAttributeName : FnoxButtonTitleColor()
                                      }];
}

void StyleApprovalHeading(NSTextField* heading, NSString* title, NSString* credentials) {
  NSMutableAttributedString* text = [[NSMutableAttributedString alloc]
      initWithString:title
          attributes:@{
            NSFontAttributeName : [NSFont boldSystemFontOfSize:14],
            NSForegroundColorAttributeName : FnoxHeadingColor()
          }];
  NSMutableParagraphStyle* paragraph = [NSMutableParagraphStyle new];
  paragraph.alignment = NSTextAlignmentCenter;
  [text addAttribute:NSParagraphStyleAttributeName
               value:paragraph
               range:NSMakeRange(0, text.length)];
  const NSRange delimiter = [title rangeOfString:@" to use "];
  if (delimiter.location != NSNotFound) {
    NSUInteger offset = NSMaxRange(delimiter);
    NSFont* credentialFont = [NSFont monospacedSystemFontOfSize:13 weight:NSFontWeightSemibold];
    for (NSString* name in [credentials componentsSeparatedByString:@", "]) {
      if (name.length == 0 || offset >= title.length) continue;
      const NSRange range = [title rangeOfString:name
                                         options:0
                                           range:NSMakeRange(offset, title.length - offset)];
      if (range.location == NSNotFound) continue;
      [text addAttribute:NSFontAttributeName value:credentialFont range:range];
      offset = NSMaxRange(range);
    }
  }
  heading.attributedStringValue = text;
}

struct PanelSpringPhase {
  CGFloat progress;
  CGFloat displacement;
};

constexpr PanelSpringPhase kPanelSpringPhases[] = {
    {0, 0}, {0.18, 1}, {0.46, -0.5}, {0.74, 1.0 / 6}, {1, 0}};
constexpr CGFloat kPanelControlTravel = 40;
constexpr NSTimeInterval kPanelControlDuration = 0.16;

NSRect CenteredPanelFrame(NSRect frame, CGFloat width, CGFloat height) {
  const CGFloat centerX = NSMidX(frame);
  const CGFloat centerY = NSMidY(frame);
  return NSMakeRect(centerX - width / 2, centerY - height / 2, width, height);
}

CGFloat PanelSpringDisplacement(CGFloat progress) {
  NSUInteger phaseIndex = 1;
  while (phaseIndex < sizeof(kPanelSpringPhases) / sizeof(kPanelSpringPhases[0]) &&
         progress > kPanelSpringPhases[phaseIndex].progress) {
    ++phaseIndex;
  }
  const PanelSpringPhase start = kPanelSpringPhases[phaseIndex - 1];
  const PanelSpringPhase end = kPanelSpringPhases[phaseIndex];
  const CGFloat local = (progress - start.progress) / (end.progress - start.progress);
  const CGFloat eased = (1 - std::cos(3.141592653589793 * local)) / 2;
  return start.displacement + (end.displacement - start.displacement) * eased;
}

void InvalidateCursorRects(NSArray<NSView*>* views) {
  for (NSView* view in views) {
    if (view.window != nil) {
      [view.window invalidateCursorRectsForView:view];
    }
  }
}

void AnimatePanelFrame(NSPanel* panel, NSRect start, NSRect target, BOOL reduceMotion,
                       NSArray<NSView*>* trackingViews, NSArray<NSValue*>* trackingFrames,
                       NSSize trackingContentSize, NSView* authenticationHost,
                       NSRect hostStartFrame,
                       NSRect hostTargetFrame, void (^completion)(void)) {
  const CGFloat contentHeightDelta = target.size.height - start.size.height;
  const CGFloat hostYDelta = hostTargetFrame.origin.y - hostStartFrame.origin.y;
  const CGFloat contentHeightRange = contentHeightDelta;
  void (^layoutAuthenticationHost)(void) = ^{
    const NSSize contentSize = ApprovalContent(panel).bounds.size;
    const CGFloat rawProgress =
        contentHeightRange == 0
            ? 1
            : (contentSize.height - trackingContentSize.height) / contentHeightRange;
    const CGFloat progress = MAX(0, MIN(1, rawProgress));
    const CGFloat hostY = hostStartFrame.origin.y + hostYDelta * progress;
    const NSRect hostFrame = AuthenticationHostFrame(contentSize, hostY);
    LayoutAuthenticationHost(authenticationHost, hostFrame);
  };
  if (reduceMotion) {
    [panel setFrame:target display:YES];
    layoutAuthenticationHost();
    InvalidateCursorRects(trackingViews);
    completion();
    return;
  }
  constexpr NSTimeInterval snapDuration = 0.14;
  constexpr NSTimeInterval settleDuration = 0.18;
  const CGFloat widthDelta = target.size.width - start.size.width;
  const CGFloat heightDelta = target.size.height - start.size.height;
  const CGFloat travel = MAX(500, MAX(std::abs(widthDelta), std::abs(heightDelta)));
  const CGFloat overshoot = travel * 0.018;
  const CGFloat widthDirection = widthDelta < 0 ? -1 : 1;
  const CGFloat heightDirection = heightDelta < 0 ? -1 : 1;
  const CGFloat centerX = NSMidX(start);
  const CGFloat centerY = NSMidY(start);
  const CFTimeInterval animationStart = CACurrentMediaTime();
  NSTimer* timer = [NSTimer
      timerWithTimeInterval:1.0 / 60.0
                    repeats:YES
                      block:^(NSTimer* currentTimer) {
                        const NSTimeInterval elapsed = CACurrentMediaTime() - animationStart;
                        if (elapsed >= snapDuration + settleDuration) {
                          [panel setFrame:target display:YES];
                          layoutAuthenticationHost();
                          [currentTimer invalidate];
                          InvalidateCursorRects(trackingViews);
                          completion();
                          return;
                        }
                        CGFloat width = target.size.width;
                        CGFloat height = target.size.height;
                        if (elapsed < snapDuration) {
                          const CGFloat progress = elapsed / snapDuration;
                          const CGFloat eased = 1 - std::pow(1 - progress, 3);
                          width = start.size.width + widthDelta * eased;
                          height = start.size.height + heightDelta * eased;
                        } else {
                          const CGFloat progress = (elapsed - snapDuration) / settleDuration;
                          const CGFloat displacement = PanelSpringDisplacement(progress);
                          width += widthDirection * overshoot * displacement;
                          height += heightDirection * overshoot * displacement;
                        }
                        const NSRect frame =
                            NSMakeRect(centerX - width / 2, centerY - height / 2, width, height);
                        [panel setFrame:frame display:YES];
                        layoutAuthenticationHost();
                        const CGFloat xOffset =
                            (ApprovalContent(panel).bounds.size.width - trackingContentSize.width) /
                            2;
                        const CGFloat yOffset = (ApprovalContent(panel).bounds.size.height -
                                                 trackingContentSize.height) /
                                                2;
                        for (NSUInteger index = 0; index < trackingViews.count; ++index) {
                          NSRect viewFrame = trackingFrames[index].rectValue;
                          viewFrame.origin.x += xOffset;
                          viewFrame.origin.y += yOffset;
                          trackingViews[index].frame = viewFrame;
                        }
                      }];
  [[NSRunLoop mainRunLoop] addTimer:timer forMode:NSRunLoopCommonModes];
}

void AnimateViewsAndFingerprint(NSArray<NSView*>* views, CGFloat alpha,
                                FnoxFingerprintView* fingerprint, NSRect fingerprintFrame,
                                NSTimeInterval duration, BOOL reduceMotion,
                                void (^completion)(void), NSArray<NSView*>* movingViews = nil,
                                NSArray<NSValue*>* movingFrames = nil,
                                NSTimeInterval movingDuration = 0) {
  NSMutableArray<NSNumber*>* startingAlphas = [NSMutableArray arrayWithCapacity:views.count];
  for (NSView* view in views) {
    [startingAlphas addObject:@(view.alphaValue)];
  }
  NSMutableArray<NSValue*>* startingFrames = [NSMutableArray arrayWithCapacity:movingViews.count];
  for (NSView* view in movingViews) {
    [startingFrames addObject:[NSValue valueWithRect:view.frame]];
  }
  const NSRect startingFrame = fingerprint.frame;
  const NSTimeInterval effectiveMovingDuration = movingDuration > 0 ? movingDuration : duration;
  if (reduceMotion || duration <= 0) {
    for (NSView* view in views) view.alphaValue = alpha;
    for (NSUInteger index = 0; index < movingViews.count; ++index) {
      movingViews[index].frame = movingFrames[index].rectValue;
    }
    fingerprint.frame = fingerprintFrame;
    InvalidateCursorRects(movingViews);
    completion();
    return;
  }
  const CFTimeInterval animationStart = CACurrentMediaTime();
  NSTimer* timer = [NSTimer
      timerWithTimeInterval:1.0 / 60.0
                    repeats:YES
                      block:^(NSTimer* currentTimer) {
                        const NSTimeInterval elapsed = CACurrentMediaTime() - animationStart;
                        const CGFloat progress = static_cast<CGFloat>(MIN(1, elapsed / duration));
                        const CGFloat eased = (1 - std::cos(3.141592653589793 * progress)) / 2;
                        const CGFloat viewProgress =
                            static_cast<CGFloat>(MIN(1, elapsed / effectiveMovingDuration));
                        const CGFloat viewEased =
                            (1 - std::cos(3.141592653589793 * viewProgress)) / 2;
                        if (elapsed >= duration) {
                          for (NSView* view in views) view.alphaValue = alpha;
                          for (NSUInteger index = 0; index < movingViews.count; ++index) {
                            movingViews[index].frame = movingFrames[index].rectValue;
                          }
                          fingerprint.frame = fingerprintFrame;
                          [currentTimer invalidate];
                          InvalidateCursorRects(movingViews);
                          completion();
                          return;
                        }
                        for (NSUInteger index = 0; index < views.count; ++index) {
                          const CGFloat startAlpha = startingAlphas[index].doubleValue;
                          const BOOL movesWithPanel = [movingViews containsObject:views[index]];
                          const NSTimeInterval alphaDuration =
                              movesWithPanel ? effectiveMovingDuration : MIN(duration, 0.09);
                          const CGFloat alphaProgress =
                              static_cast<CGFloat>(MIN(1, elapsed / alphaDuration));
                          const CGFloat alphaEased =
                              (1 - std::cos(3.141592653589793 * alphaProgress)) / 2;
                          views[index].alphaValue = startAlpha + (alpha - startAlpha) * alphaEased;
                        }
                        for (NSUInteger index = 0; index < movingViews.count; ++index) {
                          const NSRect startFrame = startingFrames[index].rectValue;
                          const NSRect targetFrame = movingFrames[index].rectValue;
                          movingViews[index].frame = NSMakeRect(
                              startFrame.origin.x +
                                  (targetFrame.origin.x - startFrame.origin.x) * viewEased,
                              startFrame.origin.y +
                                  (targetFrame.origin.y - startFrame.origin.y) * viewEased,
                              startFrame.size.width +
                                  (targetFrame.size.width - startFrame.size.width) * viewEased,
                              startFrame.size.height +
                                  (targetFrame.size.height - startFrame.size.height) * viewEased);
                        }
                        fingerprint.frame = NSMakeRect(
                            startingFrame.origin.x +
                                (fingerprintFrame.origin.x - startingFrame.origin.x) * eased,
                            startingFrame.origin.y +
                                (fingerprintFrame.origin.y - startingFrame.origin.y) * eased,
                            startingFrame.size.width +
                                (fingerprintFrame.size.width - startingFrame.size.width) * eased,
                            startingFrame.size.height +
                                (fingerprintFrame.size.height - startingFrame.size.height) * eased);
                      }];
  [[NSRunLoop mainRunLoop] addTimer:timer forMode:NSRunLoopCommonModes];
}

NSString* MakeString(std::string_view value) {
  return [[NSString alloc] initWithBytes:value.data()
                                  length:value.size()
                                encoding:NSUTF8StringEncoding];
}

NSString* CredentialSummary(const RunOptions& options) {
  NSMutableArray<NSString*>* names = [NSMutableArray array];
  for (const CredentialRequest& credential : options.credentials) {
    NSString* name = MakeString(credential.identifier);
    if (name != nil) {
      [names addObject:name];
    }
  }
  return [names componentsJoinedByString:@", "];
}

NSString* SafeDisplayValue(NSString* value) {
  NSMutableString* safe = [NSMutableString string];
  NSCharacterSet* whitespace = NSCharacterSet.whitespaceAndNewlineCharacterSet;
  NSCharacterSet* controls = NSCharacterSet.controlCharacterSet;
  for (NSUInteger index = 0; index < value.length; index++) {
    unichar character = [value characterAtIndex:index];
    const BOOL invisibleFormat = character == 0x061c || character == 0x200e ||
                                 character == 0x200f ||
                                 (character >= 0x202a && character <= 0x202e) ||
                                 (character >= 0x2066 && character <= 0x2069);
    if ([whitespace characterIsMember:character]) {
      if (safe.length > 0 && [safe characterAtIndex:safe.length - 1] != ' ') {
        [safe appendString:@" "];
      }
      continue;
    }
    if (invisibleFormat || [controls characterIsMember:character]) {
      continue;
    }
    if (character >= 0xd800 && character <= 0xdbff && index + 1 < value.length) {
      unichar next = [value characterAtIndex:index + 1];
      if (next >= 0xdc00 && next <= 0xdfff) {
        [safe appendString:[value substringWithRange:NSMakeRange(index, 2)]];
        index++;
        continue;
      }
    }
    [safe appendString:[NSString stringWithCharacters:&character length:1]];
  }
  return safe;
}

NSString* BoundedDisplayValue(NSString* value, NSUInteger limit) {
  NSString* safe = SafeDisplayValue(value ?: @"");
  if (safe.length > limit) {
    NSRange lastCharacter = [safe rangeOfComposedCharacterSequenceAtIndex:limit];
    return [[safe substringToIndex:lastCharacter.location] stringByAppendingString:@"…"];
  }
  return safe;
}

NSArray<NSArray<NSString*>*>* RequestDetailRows(const RunOptions& options,
                                                std::string_view request_id, NSString* operation) {
  NSString* executable = MakeString(options.executable.canonical_path) ?: @"";
  NSString* command = options.invoking_command.empty()
                          ? (executable.lastPathComponent ?: executable)
                          : (MakeString(options.invoking_command) ?: @"");
  NSString* project = MakeString(options.project_directory) ?: @"";
  NSString* fullCommand = SafeDisplayValue(command);
  NSString* fullProject = SafeDisplayValue(project);
  command = BoundedDisplayValue(fullCommand, 80);
  project = BoundedDisplayValue(fullProject, 80);
  NSString* secret = BoundedDisplayValue(CredentialSummary(options) ?: @"", 80);
  NSString* source = BoundedDisplayValue(MakeString(options.credential_source) ?: @"", 80);
  NSString* service = BoundedDisplayValue(MakeString(options.credential_scope) ?: @"", 60);
  const bool systemVerification = options.system_verification || fnox::IsSystemVerification();
  NSString* approval = systemVerification
      ? (options.credential_access ? @"Touch ID required for this Keychain read"
                                   : @"Touch ID · verification only, no credential access")
      : fnox::IsScreenshotMode() ? @"Touch ID" : @"Touch ID · Shift + Return in preview";
  NSString* request = MakeString(request_id);
  if (request.length > 12) request = [request substringToIndex:12];
  return @[
    @[ @"Fnox request", request, request ],
    @[ @"Action", operation, operation ],
    @[ @"Command (unverified)", command, fullCommand ],
    @[ @"Project (unverified)", project, fullProject ],
    @[ @"Keychain service (unverified)", service, service ],
    @[ @"Secret", secret, secret ],
    @[ @"Credential source", source, source ],
    @[ @"Approval", approval, approval ],
  ];
}

NSScrollView* DetailRowsView(NSArray<NSArray<NSString*>*>* rows) {
  NSScreen* screen = NSApp.mainWindow.screen != nil ? NSApp.mainWindow.screen : NSScreen.mainScreen;
  const CGFloat width = MIN(720, screen.visibleFrame.size.width - 48);
  const CGFloat buttonWidth = 168;
  const CGFloat valueWidth = width - 24 - buttonWidth - 12;
  NSFont* font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
  NSView* document = [[FnoxDetailRowsView alloc] initWithFrame:NSMakeRect(0, 0, width - 24, 0)];
  CGFloat top = 4;
  for (NSArray<NSString*>* row in rows) {
    FnoxDetailCopyButton* button =
        [[FnoxDetailCopyButton alloc] initWithFrame:NSMakeRect(0, top + 1, buttonWidth, 24)];
    button.title = [NSString stringWithFormat:@"\u2009%@", row[0]];
    button.imagePosition = NSImageLeft;
    button.imageHugsTitle = NO;
    button.font = [NSFont systemFontOfSize:12];
    button.alignment = NSTextAlignmentLeft;
    button.bezelStyle = NSBezelStyleRounded;
    button.focusRingType = NSFocusRingTypeNone;
    button.payload = row[2];
    button.detailName = row[0];
    [button setCopied:NO];
    button.target = button;
    button.action = @selector(copyDetail:);
    [document addSubview:button];
    NSString* shown = row[1];
    const NSRect measured = [shown
        boundingRectWithSize:NSMakeSize(valueWidth, CGFLOAT_MAX)
                     options:NSStringDrawingUsesLineFragmentOrigin | NSStringDrawingUsesFontLeading
                  attributes:@{NSFontAttributeName : font}];
    const CGFloat estimated = MAX(30, ceil(NSHeight(measured) + 4));
    NSTextField* value = [NSTextField labelWithString:shown];
    value.frame = NSMakeRect(buttonWidth + 12, top, valueWidth, estimated);
    value.font = font;
    value.textColor = FnoxHeadingColor();
    value.selectable = YES;
    value.maximumNumberOfLines = 0;
    value.lineBreakMode = NSLineBreakByCharWrapping;
    value.usesSingleLineMode = NO;
    NSTextFieldCell* valueCell = (NSTextFieldCell*)value.cell;
    valueCell.wraps = YES;
    valueCell.scrollable = NO;
    value.accessibilityLabel = row[0];
    if (row.count > 3 && row[3].length > 0) {
      value.toolTip = row[3];
      value.accessibilityHelp = row[3];
    }
    [document addSubview:value];
    top += estimated + 7;
  }
  document.frame = NSMakeRect(0, 0, width - 24, top + 4);
  const CGFloat height = MIN(top + 4, MAX(180, screen.visibleFrame.size.height - 280));
  NSScrollView* scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, width, height)];
  scroll.wantsLayer = YES;
  scroll.contentView.wantsLayer = YES;
  scroll.contentView.layer.masksToBounds = YES;
  scroll.hasVerticalScroller = YES;
  scroll.hasHorizontalScroller = NO;
  scroll.autohidesScrollers = YES;
  scroll.drawsBackground = NO;
  scroll.documentView = document;
  [scroll.contentView scrollToPoint:NSZeroPoint];
  [scroll reflectScrolledClipView:scroll.contentView];
  return scroll;
}

}  // namespace

static bool ShowApprovalPromptImpl(const RunOptions& options, std::string_view request_id,
                                   TouchIdAuthorization& context, std::string_view reason,
                                   TouchIdError& error) {
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp finishLaunching];
    NSString* credentials = CredentialSummary(options);
    NSString* command = options.invoking_command.empty()
                            ? MakeString(options.executable.canonical_path).lastPathComponent
                            : MakeString(options.invoking_command);
    command = BoundedDisplayValue(command ?: @"Unknown command", 48);
    NSString* title = credentials.length > 0
                          ? [NSString stringWithFormat:@"Unverified command: %@ · Allow access to %@?", command, BoundedDisplayValue(credentials, 28)]
                          : MakeString(reason);
    NSPanel* panel = RequestPanel(360, 256, title);
    FnoxPanelButton* cancel =
        PanelButton(panel, @"Cancel", NSMakeRect(62, 18, 112, 30), NSAlertFirstButtonReturn);
    cancel.keyEquivalent = @"\033";
    ((NSButtonCell*)cancel.cell).highlightsBy = NSNoCellMask;
    cancel.contentTintColor = fnox::ApprovalCancelTitleColor(cancel.effectiveAppearance);
    cancel.attributedTitle = [[NSAttributedString alloc]
        initWithString:@"Cancel"
            attributes:@{
              NSFontAttributeName : cancel.font,
              NSForegroundColorAttributeName :
                  fnox::ApprovalCancelTitleColor(cancel.effectiveAppearance)
            }];
    cancel.showsLinkCursor = YES;
    panel.initialFirstResponder = cancel;
    FnoxPanelButton* details =
        PanelButton(panel, @"Details", NSMakeRect(186, 18, 112, 30), NSAlertSecondButtonReturn);
    details.image = [NSImage imageWithSystemSymbolName:@"chevron.right"
                              accessibilityDescription:@"Expand details"];
    details.imagePosition = NSImageRight;
    details.imageHugsTitle = YES;
    StyleBrandButtonTitle(details, @"Details");
    details.showsLinkCursor = YES;
    details.toolTip = @"Show Touch ID request details";
    details.accessibilityLabel = details.toolTip;
    FnoxInstructionLabel* instruction = [[FnoxInstructionLabel alloc] initWithFrame:NSZeroRect];
    instruction.stringValue = options.system_verification || fnox::IsSystemVerification()
                                  ? @"Verify with Touch ID"
                                  : @"Touch ID to continue";
    instruction.bezeled = NO;
    instruction.drawsBackground = NO;
    instruction.focusRingType = NSFocusRingTypeNone;
    instruction.frame = NSMakeRect(50, 176, 260, 20);
    instruction.alignment = NSTextAlignmentCenter;
    instruction.selectable = NO;
    [ApprovalContent(panel) addSubview:instruction];
    FnoxTextShimmer* instructionShimmer = [[FnoxTextShimmer alloc] initWithLabel:instruction];
    NSFont* compactInstructionFont = instruction.font;
    [instructionShimmer setEnabled:YES];
    NSView* authenticationHost = [[NSView alloc]
        initWithFrame:AuthenticationHostFrame(ApprovalContent(panel).bounds.size, 72)];
    authenticationHost.wantsLayer = YES;
    authenticationHost.layer.masksToBounds = YES;
    // Real verification uses the unobscured OS-owned LAContext dialog. Never
    // mask an embedded authentication view with our decorative fingerprint.
    FnoxFingerprintView* fingerprint =
        [[FnoxFingerprintView alloc] initWithFrame:authenticationHost.frame];
    fingerprint.accessibilityLabel = @"Touch ID fingerprint";
    [ApprovalContent(panel) addSubview:authenticationHost];
    const NSRect compactFingerprintFrame = authenticationHost.frame;
    PrepareFingerprintForAuthentication(ApprovalContent(panel), authenticationHost,
                                        fingerprint,
                                        compactFingerprintFrame);
    [ApprovalContent(panel) addSubview:instruction positioned:NSWindowAbove relativeTo:fingerprint];
    [panel center];
    NSRect panelFrame = panel.frame;
    panelFrame.origin.y -= 10;
    [panel setFrame:panelFrame display:NO];
    NSTextField* heading = PanelHeading(panel);
    const NSSize compactPanelSize = panel.frame.size;
    NSArray<NSView*>* compactViews = @[ heading, cancel, details, instruction ];
    NSMutableArray<NSValue*>* compactFrameValues =
        [NSMutableArray arrayWithCapacity:compactViews.count];
    for (NSView* view in compactViews) {
      [compactFrameValues addObject:[NSValue valueWithRect:view.frame]];
    }
    NSArray<NSValue*>* compactFrames = [compactFrameValues copy];
    const NSSize compactContentSize = ApprovalContent(panel).bounds.size;
    StyleApprovalHeading(heading, title, credentials);
    const BOOL reduceMotion = NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion;
    __block NSScrollView* detailRows = nil;
    __block NSArray<NSView*>* expandedViews = nil;
    __block NSArray<NSValue*>* expandedFrames = nil;
    __block NSSize expandedContentSize = NSZeroSize;
    __block NSRect expandedAuthenticationFrame = NSZeroRect;
    __block BOOL showingDetails = NO;
    __block BOOL transitioningDetails = NO;
    __block BOOL verifying = NO;
    __block NSArray<NSView*>* keyboardControls = @[ cancel, details ];
    __block NSUInteger keyboardFocusIndex = 0;
    __block BOOL showKeyboardHint = NO;
    NSTimer* previewHintTimer =
        (fnox::IsScreenshotMode() || options.system_verification || fnox::IsSystemVerification())
            ? nil
            : [NSTimer scheduledTimerWithTimeInterval:2.8
                                              repeats:YES
                                                block:^(NSTimer* timer) {
                                                  (void)timer;
                                                  if (verifying) return;
                                                  showKeyboardHint = !showKeyboardHint;
                                                  instruction.stringValue =
                                                      showKeyboardHint ? @"⇧ + ↩ to accept"
                                                                       : @"Touch ID to continue";
                                                  [instructionShimmer update];
                                                }];
    instruction.actionHandler = ^{
      if (!transitioningDetails && !verifying) {
        [fingerprint animateNudge];
      }
    };
    void (^focusKeyboardControlAt)(NSUInteger) = ^(NSUInteger index) {
      if (index >= keyboardControls.count) return;
      NSView* control = keyboardControls[index];
      if (control.hidden || ![(NSControl*)control isEnabled]) return;
      keyboardFocusIndex = index;
      [panel makeFirstResponder:control];
      if (detailRows != nil && [control isDescendantOf:detailRows.documentView]) {
        [control scrollRectToVisible:control.bounds];
      }
    };
    void (^moveKeyboardFocus)(NSInteger) = ^(NSInteger direction) {
      const NSUInteger count = keyboardControls.count;
      if (count == 0) return;
      NSResponder* responder = panel.firstResponder;
      NSUInteger current = [responder isKindOfClass:[NSView class]]
                               ? [keyboardControls indexOfObject:(NSView*)responder]
                               : NSNotFound;
      if (current == NSNotFound) current = keyboardFocusIndex;
      for (NSUInteger step = 1; step <= count; ++step) {
        const NSInteger candidate =
            (static_cast<NSInteger>(current) + direction * static_cast<NSInteger>(step) +
             static_cast<NSInteger>(count) * 2) %
            static_cast<NSInteger>(count);
        const NSUInteger index = static_cast<NSUInteger>(candidate);
        NSView* control = keyboardControls[index];
        if (control.hidden || ![(NSControl*)control isEnabled]) continue;
        focusKeyboardControlAt(index);
        return;
      }
    };
    void (^toggleDetails)(BOOL) = ^(BOOL show) {
      if (transitioningDetails || showingDetails == show) return;
      transitioningDetails = YES;
      SetApprovalGlassTransition(panel, YES);
      details.enabled = NO;
      if (show) {
        [instructionShimmer setHighlightsVisible:NO];
        detailRows = DetailRowsView(RequestDetailRows(options, request_id, MakeString(reason)));
        const CGFloat width = detailRows.frame.size.width + 40;
        const CGFloat rowsBottom = kExpandedFooterHeight + kExpandedRowsFooterGap;
        const CGFloat height = detailRows.frame.size.height + rowsBottom + kExpandedRowsHeadingGap +
                               kExpandedHeadingHeight + kExpandedTopInset;
        detailRows.frame =
            NSMakeRect(20, rowsBottom, detailRows.frame.size.width, detailRows.frame.size.height);
        detailRows.hidden = YES;
        detailRows.alphaValue = 0;
        [ApprovalContent(panel) addSubview:detailRows];
        const NSRect hiddenCompactFrame =
            NSMakeRect(compactFingerprintFrame.origin.x, -104, compactFingerprintFrame.size.width,
                       compactFingerprintFrame.size.height);
        expandedAuthenticationFrame = AuthenticationHostFrame(NSMakeSize(width, height), 0);
        NSArray<NSValue*>* exitingButtonFrames = @[
          [NSValue valueWithRect:NSOffsetRect(cancel.frame, -kPanelControlTravel, 0)],
          [NSValue valueWithRect:NSOffsetRect(details.frame, kPanelControlTravel, 0)]
        ];
        AnimateViewsAndFingerprint(
            @[ heading, cancel, details, instruction ], 0, fingerprint, hiddenCompactFrame, 0.22,
            reduceMotion,
            ^{
              cancel.hidden = YES;
              details.hidden = YES;
              instruction.hidden = YES;
              fingerprint.alphaValue = 0;
              fingerprint.hidden = YES;
              const NSRect expandedFrame = CenteredPanelFrame(panel.frame, width, height);
              AnimatePanelFrame(
                  panel, panel.frame, expandedFrame, reduceMotion, compactViews, compactFrames,
                  compactContentSize, authenticationHost,
                  compactFingerprintFrame, expandedAuthenticationFrame, ^{
                    heading.stringValue = @"Touch ID request details";
                    heading.frame =
                        NSMakeRect(20, height - kExpandedTopInset - kExpandedHeadingHeight,
                                   width - 40, kExpandedHeadingHeight);
                    heading.alignment = NSTextAlignmentCenter;
                    detailRows.hidden = NO;
                    detailRows.alphaValue = 0;
                    details.title = @"";
                    StyleBrandButtonTitle(details, @"");
                    details.image = [NSImage imageWithSystemSymbolName:@"chevron.left"
                                              accessibilityDescription:@"Back to approval"];
                    details.imagePosition = NSImageOnly;
                    details.showsLinkCursor = YES;
                    [details resetCursorRects];
                    const NSRect expandedDetailsFrame =
                        NSMakeRect(20, kFingerprintClipBottomInset, 36, 30);
                    details.frame = NSOffsetRect(expandedDetailsFrame, -kPanelControlTravel, 0);
                    details.toolTip = @"Return to approval";
                    details.accessibilityLabel = details.toolTip;
                    details.hidden = NO;
                    instruction.font = [NSFont systemFontOfSize:14];
                    const NSRect expandedInstructionFrame =
                        NSMakeRect(width - 220, kFingerprintClipBottomInset - 8, 200, 30);
                    instruction.frame =
                        NSOffsetRect(expandedInstructionFrame, kPanelControlTravel, 0);
                    instruction.alignment = NSTextAlignmentRight;
                    instruction.hidden = NO;
                    [instructionShimmer setHighlightsVisible:YES];
                    expandedViews = @[ heading, detailRows, details, instruction ];
                    expandedFrames = @[
                      [NSValue valueWithRect:heading.frame],
                      [NSValue valueWithRect:detailRows.frame],
                      [NSValue valueWithRect:expandedDetailsFrame],
                      [NSValue valueWithRect:expandedInstructionFrame]
                    ];
                    expandedContentSize = ApprovalContent(panel).bounds.size;
                    fingerprint.alphaValue = 0;
                    fingerprint.hidden = YES;
                    AnimateViewsAndFingerprint(
                        @[ heading, detailRows, details, instruction ], 1, fingerprint,
                        expandedAuthenticationFrame, 0.16, reduceMotion,
                        ^{
                          [instructionShimmer update];
                          showingDetails = YES;
                          transitioningDetails = NO;
                          SetApprovalGlassTransition(panel, NO);
                          details.enabled = YES;
                          NSMutableArray<NSView*>* expandedKeyboardControls =
                              [NSMutableArray arrayWithObject:details];
                          NSView* firstDetailControl = nil;
                          for (NSView* control in detailRows.documentView.subviews) {
                            if (![control isKindOfClass:[FnoxDetailCopyButton class]]) {
                              continue;
                            }
                            if (firstDetailControl == nil) firstDetailControl = control;
                            [expandedKeyboardControls addObject:control];
                          }
                          keyboardControls = [expandedKeyboardControls copy];
                          const NSUInteger firstDetailIndex =
                              firstDetailControl != nil
                                  ? [keyboardControls indexOfObject:firstDetailControl]
                                  : 0;
                          focusKeyboardControlAt(firstDetailIndex);
                          if (firstDetailControl == nil) {
                            focusKeyboardControlAt(0);
                          }
                        },
                        @[ details, instruction ],
                        @[
                          [NSValue valueWithRect:expandedDetailsFrame],
                          [NSValue valueWithRect:expandedInstructionFrame]
                        ],
                        kPanelControlDuration);
                  });
            },
            @[ cancel, details ], @[ exitingButtonFrames[0], exitingButtonFrames[1] ],
            kPanelControlDuration);
        return;
      }
      const NSRect offscreenExpandedFrame =
          NSOffsetRect(fingerprint.frame, 0, -104 - fingerprint.frame.origin.y);
      const NSRect backOffscreenFrame = NSOffsetRect(details.frame, -kPanelControlTravel, 0);
      const NSRect instructionOffscreenFrame =
          NSOffsetRect(instruction.frame, kPanelControlTravel, 0);
      AnimateViewsAndFingerprint(
          @[ heading, detailRows, details, instruction ], 0, fingerprint, offscreenExpandedFrame,
          0.22, reduceMotion,
          ^{
            detailRows.hidden = YES;
            details.hidden = YES;
            instruction.hidden = YES;
            fingerprint.alphaValue = 0;
            fingerprint.hidden = YES;
            const NSRect compactFrame =
                CenteredPanelFrame(panel.frame, compactPanelSize.width, compactPanelSize.height);
            AnimatePanelFrame(
                panel, panel.frame, compactFrame, reduceMotion, expandedViews, expandedFrames,
                expandedContentSize, authenticationHost,
                expandedAuthenticationFrame, compactFingerprintFrame, ^{
                  StyleApprovalHeading(heading, title, credentials);
                  heading.alignment = NSTextAlignmentCenter;
                  instruction.font = compactInstructionFont;
                  instruction.alignment = NSTextAlignmentCenter;
                  details.title = @"Details";
                  StyleBrandButtonTitle(details, @"Details");
                  details.image = [NSImage imageWithSystemSymbolName:@"chevron.right"
                                            accessibilityDescription:@"Expand details"];
                  details.imagePosition = NSImageRight;
                  details.imageHugsTitle = YES;
                  details.showsLinkCursor = YES;
                  [details resetCursorRects];
                  details.frame = compactFrames[2].rectValue;
                  details.toolTip = @"Show Touch ID request details";
                  details.accessibilityLabel = details.toolTip;
                  for (NSUInteger index = 0; index < compactViews.count; ++index) {
                    compactViews[index].frame = compactFrames[index].rectValue;
                  }
                  fingerprint.frame = NSOffsetRect(compactFingerprintFrame, 0, -104);
                  fingerprint.hidden = NO;
                  fingerprint.alphaValue = 0;
                  cancel.hidden = NO;
                  details.hidden = NO;
                  instruction.hidden = verifying;
                  [instructionShimmer setHighlightsVisible:!verifying];
                  if (verifying) {
                    cancel.alphaValue = 0;
                    details.alphaValue = 0;
                    heading.alphaValue = 1;
                    AnimateViewsAndFingerprint(@[ fingerprint ], 1, fingerprint,
                                               compactFingerprintFrame, 0.16, reduceMotion, ^{
                                                 [instructionShimmer update];
                                                 showingDetails = NO;
                                                 transitioningDetails = NO;
                                                 SetApprovalGlassTransition(panel, NO);
                                                 details.enabled = YES;
                                                 keyboardControls = @[ cancel, details ];
                                                 focusKeyboardControlAt(1);
                                               });
                    return;
                  }
                  cancel.frame = NSOffsetRect(compactFrames[1].rectValue, -kPanelControlTravel, 0);
                  details.frame = NSOffsetRect(compactFrames[2].rectValue, kPanelControlTravel, 0);
                  cancel.alphaValue = 0;
                  details.alphaValue = 0;
                  AnimateViewsAndFingerprint(
                      @[ fingerprint, cancel, details ], 1, fingerprint, compactFingerprintFrame,
                      kPanelControlDuration, reduceMotion,
                      ^{
                        AnimateViewsAndFingerprint(@[ heading, instruction ], 1, fingerprint,
                                                   fingerprint.frame, 0.07, reduceMotion, ^{
                                                     [instructionShimmer update];
                                                     showingDetails = NO;
                                                     transitioningDetails = NO;
                                                     SetApprovalGlassTransition(panel, NO);
                                                     details.enabled = YES;
                                                     keyboardControls = @[ cancel, details ];
                                                     focusKeyboardControlAt(1);
                                                   });
                      },
                      @[ cancel, details ],
                      @[
                        [NSValue valueWithRect:compactFrames[1].rectValue],
                        [NSValue valueWithRect:compactFrames[2].rectValue]
                      ],
                      kPanelControlDuration);
                });
          },
          @[ details, instruction ],
          @[
            [NSValue valueWithRect:backOffscreenFrame],
            [NSValue valueWithRect:instructionOffscreenFrame]
          ],
          kPanelControlDuration);
    };
    [NSApp activate];
    [panel makeKeyAndOrderFront:nil];
    NSModalSession session = [NSApp beginModalSessionForWindow:panel];
    bool cancelled = false;
    __block BOOL escapePressed = NO;
    details.actionHandler = ^{
      toggleDetails(showingDetails == NO);
    };
    id authenticationClickMonitor = [NSEvent
        addLocalMonitorForEventsMatchingMask:NSEventMaskLeftMouseDown
                                     handler:^NSEvent*(NSEvent* event) {
                                       if (event.window == panel) {
                                         ((FnoxApprovalPanel*)panel).keyboardFocusVisible = NO;
                                         for (NSView* control in keyboardControls)
                                           [control setNeedsDisplay:YES];
                                       }
                                       if (event.window != panel || transitioningDetails ||
                                           verifying) {
                                         return event;
                                       }
                                       const NSPoint point = [ApprovalContent(panel)
                                           convertPoint:event.locationInWindow
                                               fromView:nil];
                                       const NSRect authenticationFrame =
                                           [authenticationHost convertRect:authenticationHost.bounds
                                                                    toView:ApprovalContent(panel)];
                                       if (NSPointInRect(point, authenticationFrame) ||
                                           NSPointInRect(point, fingerprint.frame)) {
                                         [fingerprint animateNudge];
                                       }
                                       return event;
                                     }];
    id keyboardMonitor = [NSEvent
        addLocalMonitorForEventsMatchingMask:NSEventMaskKeyDown
                                     handler:^NSEvent*(NSEvent* event) {
                                       if (event.window != panel) {
                                         return event;
                                       }
                                       const NSUInteger key = event.keyCode;
                                       if (key == 53) {
                                         escapePressed = YES;
                                         [NSApp stopModalWithCode:NSAlertFirstButtonReturn];
                                         return nil;
                                       }
                                       if (verifying || transitioningDetails) return event;
                                       if (!options.system_verification &&
                                           !fnox::IsSystemVerification() &&
                                           (key == 36 || key == 76) &&
                                           (event.modifierFlags & NSEventModifierFlagShift) != 0) {
                                         FnoxPreviewAcceptTouchId();
                                         return nil;
                                       }
                                       NSResponder* responder = panel.firstResponder;
                                       const NSUInteger focusedIndex =
                                           [responder isKindOfClass:[NSView class]]
                                               ? [keyboardControls indexOfObject:(NSView*)responder]
                                               : NSNotFound;
                                       if (key == 48 || ((key == 123 || key == 124) &&
                                                         focusedIndex != NSNotFound)) {
                                         if (key == 48)
                                           ((FnoxApprovalPanel*)panel).keyboardFocusVisible = YES;
                                         for (NSView* control in keyboardControls)
                                           [control setNeedsDisplay:YES];
                                         NSInteger direction = key == 123 ? -1 : 1;
                                         if (key == 48 && (event.modifierFlags &
                                                           NSEventModifierFlagShift) != 0) {
                                           direction = -1;
                                         }
                                         moveKeyboardFocus(direction);
                                         return nil;
                                       }
                                       if (key == 36 || key == 49) {
                                         const NSUInteger index =
                                             [responder isKindOfClass:[NSView class]]
                                                 ? [keyboardControls
                                                       indexOfObject:(NSView*)responder]
                                                 : NSNotFound;
                                         if (index != NSNotFound &&
                                             [keyboardControls[index]
                                                 isKindOfClass:[NSButton class]]) {
                                           [(NSButton*)keyboardControls[index] performClick:nil];
                                           return nil;
                                         }
                                       }
                                       return event;
                                     }];
    auto readinessDeadline = std::chrono::steady_clock::now() + kApprovalReadinessTimeout;
    bool hasActivated = NSApp.isActive;
    auto readiness = fnox::ApprovalReadinessStatus::kWaiting;
    while (readiness == fnox::ApprovalReadinessStatus::kWaiting) {
      const NSModalResponse response = [NSApp runModalSession:session];
      if (response != NSModalResponseContinue) {
        cancelled = true;
      }
      if (cancelled) {
        readiness = fnox::ApprovalReadinessStatus::kCancelled;
        break;
      }
      // Bound failed initial activation, but allow switching away after activation.
      hasActivated = hasActivated || NSApp.isActive;
      if (hasActivated && !NSApp.isActive) {
        readinessDeadline = std::chrono::steady_clock::now() + kApprovalReadinessTimeout;
      } else if (std::chrono::steady_clock::now() >= readinessDeadline) {
        readiness = fnox::ApprovalReadinessStatus::kUnavailable;
        break;
      }
      readiness = (NSApp.isActive && panel.isKeyWindow && panel.isVisible && panel.alphaValue > 0)
                      ? fnox::ApprovalReadinessStatus::kReady
                      : fnox::ApprovalReadinessStatus::kWaiting;
      if (readiness == fnox::ApprovalReadinessStatus::kWaiting) {
        const double remaining =
            std::chrono::duration<double>(readinessDeadline - std::chrono::steady_clock::now())
                .count();
        [[NSRunLoop currentRunLoop]
            runUntilDate:[NSDate dateWithTimeIntervalSinceNow:std::min(0.01, remaining)]];
      }
    }
    const bool authenticated =
        readiness == fnox::ApprovalReadinessStatus::kReady &&
        context.AuthenticateWithEvents(reason, error, [&cancelled, &session, &context] {
          if (cancelled) return;
          const NSModalResponse response = [NSApp runModalSession:session];
          if (response == NSModalResponseContinue) return;
          cancelled = true;
          context.Invalidate();
        });
    if (authenticated && !cancelled) {
      NSDate* scanStartedAt = nil;
      while (transitioningDetails) {
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0 / 60.0]];
      }
      [instructionShimmer setEnabled:NO];
      instruction.hidden = YES;
      if (showingDetails) {
        verifying = YES;
        cancel.enabled = NO;
        cancel.keyEquivalent = @"";
        details.enabled = NO;
        toggleDetails(NO);
        while (transitioningDetails) {
          [[NSRunLoop currentRunLoop]
              runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0 / 60.0]];
        }
      }
      cancelled = cancelled || escapePressed;
      const bool fingerprintVisible = PresentAuthenticatedFingerprint(
          ApprovalContent(panel), fingerprint,
          [authenticationHost convertRect:authenticationHost.bounds toView:ApprovalContent(panel)],
          authenticated, cancelled);
      if (!fingerprintVisible) {
        cancelled = true;
      } else {
        cancel.enabled = NO;
        cancel.keyEquivalent = @"";
        details.enabled = NO;
        scanStartedAt = [NSDate date];
        fingerprint.accessibilityLabel = options.system_verification || fnox::IsSystemVerification()
                                             ? @"User verified"
                                             : @"Simulated approval";
        [fingerprint animateSuccess];
        if (NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion) {
          cancel.alphaValue = 0;
          details.alphaValue = 0;
        } else {
          [NSAnimationContext
              runAnimationGroup:^(NSAnimationContext* animation) {
                animation.duration = 0.45;
                animation.timingFunction =
                    [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
                cancel.animator.alphaValue = 0;
                details.animator.alphaValue = 0;
              }
              completionHandler:nil];
        }
        const NSTimeInterval duration = FnoxFingerprintApprovalDuration(
            NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion);
        NSDate* deadline = [scanStartedAt dateByAddingTimeInterval:duration];
        while (deadline.timeIntervalSinceNow > 0 && !escapePressed) {
          const NSModalResponse response = [NSApp runModalSession:session];
          if (response == NSAlertSecondButtonReturn) {
            [NSApp endModalSession:session];
            session = [NSApp beginModalSessionForWindow:panel];
            continue;
          }
          if (response != NSModalResponseContinue) {
            cancelled = true;
            break;
          }
          [NSRunLoop.currentRunLoop
              runUntilDate:[NSDate
                               dateWithTimeIntervalSinceNow:MIN(0.01,
                                                                deadline.timeIntervalSinceNow)]];
        }
      }
    }
    cancelled = cancelled || escapePressed;
    [NSApp endModalSession:session];
    if (cancelled) {
      while (transitioningDetails) {
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
      }
      __block BOOL dismissed = NO;
      [NSAnimationContext
          runAnimationGroup:^(NSAnimationContext* animation) {
            animation.duration = reduceMotion ? 0.12 : 0.1;
            animation.timingFunction =
                [CAMediaTimingFunction functionWithControlPoints:0.12f:0.8f:0.2f:1.0f];
            if (!reduceMotion) {
              const NSRect frame = panel.frame;
              [panel.animator
                  setFrame:NSInsetRect(frame, -NSWidth(frame) * 0.09, -NSHeight(frame) * 0.09)
                   display:YES];
            }
            panel.animator.alphaValue = 0;
          }
          completionHandler:^{
            dismissed = YES;
          }];
      while (!dismissed) {
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
      }
    }
    [panel orderOut:nil];
    [previewHintTimer invalidate];
    [NSEvent removeMonitor:authenticationClickMonitor];
    [NSEvent removeMonitor:keyboardMonitor];
    if (cancelled) {
      context.Invalidate();
      error.status = TouchIdStatus::kCancelled;
      error.detail = "Approval cancelled.";
      return false;
    }
    if (readiness == fnox::ApprovalReadinessStatus::kUnavailable) {
      context.Invalidate();
      error.status = TouchIdStatus::kUnavailable;
      error.os_status = 0;
      error.detail = "Authentication unavailable: approval interface did not become "
                     "active and visible.";
      return false;
    }
    return authenticated;
  }
}

bool ShowApprovalPrompt(const RunOptions& options, std::string_view request_id,
                        TouchIdAuthorization& context, std::string_view reason,
                        TouchIdError& error) {
  return ShowApprovalPromptImpl(options, request_id, context, reason, error);
}

}  // namespace fnox
