#import "fingerprint-view.h"
#import <QuartzCore/QuartzCore.h>
#include <algorithm>
#include <cmath>
#import "approval-button-style.h"
#include "fingerprint-animation.generated.h"

double FnoxFingerprintApprovalDuration(BOOL reduceMotion) {
  return reduceMotion ? kFingerprintReducedMotionDuration : kFingerprintApprovalDuration;
}

namespace {
constexpr CGFloat kFingerprintNudgeDistance = 1.25;
constexpr CFTimeInterval kFingerprintNudgeDuration = 0.18;

void ScaleFingerprintLayers(CALayer* layer, CGFloat scale) {
  if (layer == nil) return;
  layer.contentsScale = std::max<CGFloat>(1, scale);
  ScaleFingerprintLayers(layer.mask, scale);
  for (CALayer* child in layer.sublayers) ScaleFingerprintLayers(child, scale);
}
CGColorRef FingerprintColor(uint32_t color) {
  return [NSColor colorWithSRGBRed:((color >> 16) & 255) / 255.0
                             green:((color >> 8) & 255) / 255.0
                              blue:(color & 255) / 255.0
                             alpha:1]
      .CGColor;
}
CAShapeLayer* FingerprintShape(CGPathRef path, CGFloat scale) {
  CAShapeLayer* shape = [CAShapeLayer layer];
  shape.path = path;
  shape.fillColor = nil;
  shape.strokeColor = NSColor.whiteColor.CGColor;
  shape.lineWidth = kFingerprintStrokeWidth * scale;
  shape.lineCap = kCALineCapRound;
  shape.lineJoin = kCALineJoinRound;
  return shape;
}
}  // namespace

@interface FnoxFingerprintView ()
@property(nonatomic, strong) CALayer* imageLayer;
@property(nonatomic, strong) CALayer* inkLayer;
@property(nonatomic, strong) NSArray<CAShapeLayer*>* ridges;
@property(nonatomic, strong) NSArray<CAShapeLayer*>* trails;
@property(nonatomic, strong) NSArray<CAShapeLayer*>* highlights;
@property(nonatomic, strong) CAShapeLayer* ring;
@property(nonatomic, strong) CAShapeLayer* check;
@property(nonatomic, strong) NSTimer* timer;
@property(nonatomic) CFTimeInterval startedAt;
@property(nonatomic) unsigned sampleIndex;
- (void)renderSample:(unsigned)index;
- (void)tickAnimation;
@end

@implementation FnoxFingerprintView
- (instancetype)initWithFrame:(NSRect)frame {
  self = [super initWithFrame:frame];
  if (self == nil) return nil;
  self.wantsLayer = YES;
  self.layer.backgroundColor = NSColor.clearColor.CGColor;
  self.layer.masksToBounds = YES;
  self.imageLayer = [CALayer layer];
  self.imageLayer.frame = self.bounds;
  [self.layer addSublayer:self.imageLayer];
  self.inkLayer = [CALayer layer];
  self.inkLayer.frame = self.bounds;
  CALayer* mask = [CALayer layer];
  mask.frame = self.bounds;
  self.inkLayer.mask = mask;
  [self.imageLayer addSublayer:self.inkLayer];
  NSMutableArray<CAShapeLayer*>* ridges = [NSMutableArray array];
  NSMutableArray<CAShapeLayer*>* trails = [NSMutableArray array];
  NSMutableArray<CAShapeLayer*>* highlights = [NSMutableArray array];
  const CGFloat scale = NSWidth(self.bounds) / 288;
  const CGAffineTransform transform =
      CGAffineTransformMake(scale, 0, 0, -scale, 0, NSHeight(self.bounds));
  for (unsigned index = 0; index < kFingerprintRidgeCount; ++index) {
    CGPathRef path = CreateFingerprintRidge(index, &transform);
    CAShapeLayer* ridge = FingerprintShape(path, scale);
    CAShapeLayer* trail = FingerprintShape(path, scale);
    CAShapeLayer* highlight = FingerprintShape(path, scale);
    [mask addSublayer:ridge];
    [self.imageLayer addSublayer:trail];
    [ridges addObject:ridge];
    [trails addObject:trail];
    [highlights addObject:highlight];
    CGPathRelease(path);
  }
  for (CAShapeLayer* highlight in highlights) [self.imageLayer addSublayer:highlight];
  self.ridges = ridges;
  self.trails = trails;
  self.highlights = highlights;
  self.ring = FingerprintShape(nullptr, scale);
  self.check = FingerprintShape(nullptr, scale);
  self.check.lineWidth = 16 * scale;
  [self.imageLayer addSublayer:self.ring];
  [self.imageLayer addSublayer:self.check];
  ScaleFingerprintLayers(self.layer, NSScreen.mainScreen.backingScaleFactor);
  [self renderSample:0];
  return self;
}
- (void)renderSample:(unsigned)index {
  self.sampleIndex = std::min(index, kFingerprintSampleCount - 1);
  const BOOL dark = [[self.effectiveAppearance
      bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]]
      isEqualToString:NSAppearanceNameDarkAqua];
  const FingerprintSample& sample = kFingerprintSamples[dark ? 1 : 0][self.sampleIndex];
  [CATransaction begin];
  [CATransaction setDisableActions:YES];
  self.inkLayer.backgroundColor = FingerprintColor(sample.tones[1]);
  for (unsigned ridge = 0; ridge < kFingerprintRidgeCount; ++ridge) {
    CAShapeLayer* base = self.ridges[ridge];
    base.opacity = static_cast<float>(1 - sample.eased);
    base.strokeStart = sample.eased / 2;
    base.strokeEnd = 1 - sample.eased / 2;
    if (ridge < 2) {
      const double progress = std::min(1.0, sample.progress / 0.3);
      base.opacity = static_cast<float>(1 - progress * progress * (3 - 2 * progress));
      base.strokeStart = 0;
      base.strokeEnd = 1;
    }
    CAShapeLayer* trail = self.trails[ridge];
    trail.strokeColor = FingerprintColor(sample.pale);
    trail.strokeStart = kFingerprintFromEnd[ridge] ? 1 - sample.visited[ridge] : 0;
    trail.strokeEnd = kFingerprintFromEnd[ridge] ? 1 : sample.visited[ridge];
    trail.opacity = sample.visited[ridge] <= 0 ? 0 : static_cast<float>(1 - sample.eased);
    CAShapeLayer* active = self.highlights[ridge];
    active.strokeColor = FingerprintColor(sample.active[ridge]);
    active.strokeStart = kFingerprintFromEnd[ridge] ? 1 - sample.extents[ridge] : 0;
    active.strokeEnd = kFingerprintFromEnd[ridge] ? 1 : sample.extents[ridge];
    active.opacity = sample.extents[ridge] <= 0 || sample.progress > 0 ? 0 : 1;
  }
  // The first animation sample already contains the incoming sweep. Keep the
  // resting state separate; only play those samples after approval starts.
  if (self.startedAt == 0) {
    self.inkLayer.backgroundColor = fnox::ApprovalRestingFill(self.effectiveAppearance).CGColor;
    for (CAShapeLayer* trail in self.trails) trail.opacity = 0;
    for (CAShapeLayer* highlight in self.highlights) highlight.opacity = 0;
  }
  const CGFloat scale = NSWidth(self.bounds) / 288;
  const CGAffineTransform transform =
      CGAffineTransformMake(scale, 0, 0, -scale, 0, NSHeight(self.bounds));
  CGMutablePathRef circle = CGPathCreateMutable();
  if (sample.span > 0) {
    CGPathAddArc(circle, &transform, kFingerprintCenterX, kFingerprintCenterY, kFingerprintRadius,
                 -M_PI_2 - sample.span / 2, -M_PI_2 + sample.span / 2, false);
    if (sample.span >= 2 * M_PI - 0.000001) CGPathCloseSubpath(circle);
  }
  self.ring.path = circle;
  self.ring.strokeColor = FingerprintColor(sample.ring);
  CGPathRelease(circle);
  CGMutablePathRef check = CGPathCreateMutable();
  CGPathMoveToPoint(check, &transform, 98, 149);
  CGPathAddLineToPoint(check, &transform, 132, 189);
  CGPathAddLineToPoint(check, &transform, sample.checkEnd[0], sample.checkEnd[1]);
  self.check.path = check;
  self.check.strokeColor = FingerprintColor(sample.check);
  self.check.opacity = static_cast<float>(sample.checkOpacity);
  CGPathRelease(check);
  [CATransaction commit];
}
- (void)viewDidChangeEffectiveAppearance {
  [super viewDidChangeEffectiveAppearance];
  if (self.imageLayer != nil) [self renderSample:self.sampleIndex];
}
- (void)viewDidChangeBackingProperties {
  [super viewDidChangeBackingProperties];
  ScaleFingerprintLayers(self.layer, self.window.backingScaleFactor);
}
- (void)viewDidMoveToWindow {
  [super viewDidMoveToWindow];
  if (self.window != nil) {
    ScaleFingerprintLayers(self.layer, self.window.backingScaleFactor);
  }
}
- (NSView*)hitTest:(NSPoint)point {
  (void)point;
  return nil;
}
- (void)animateNudge {
  if (NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion) return;
  const NSPoint origin = self.imageLayer.position;
  CAKeyframeAnimation* nudge = [CAKeyframeAnimation animationWithKeyPath:@"position"];
  nudge.values = @[
    [NSValue valueWithPoint:origin],
    [NSValue valueWithPoint:NSMakePoint(origin.x, origin.y + kFingerprintNudgeDistance)],
    [NSValue valueWithPoint:NSMakePoint(origin.x, origin.y - kFingerprintNudgeDistance)],
    [NSValue valueWithPoint:NSMakePoint(origin.x - kFingerprintNudgeDistance, origin.y)],
    [NSValue valueWithPoint:NSMakePoint(origin.x + kFingerprintNudgeDistance, origin.y)],
    [NSValue valueWithPoint:origin],
  ];
  nudge.keyTimes = @[ @0, @0.16, @0.32, @0.48, @0.64, @1 ];
  nudge.duration = kFingerprintNudgeDuration;
  nudge.calculationMode = kCAAnimationLinear;
  nudge.timingFunction =
      [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
  [self.imageLayer removeAnimationForKey:@"fingerprintNudge"];
  [self.imageLayer addAnimation:nudge forKey:@"fingerprintNudge"];
}

- (void)animateSuccess {
  if (self.startedAt != 0) return;
  self.startedAt = CACurrentMediaTime();
  if (NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion) {
    [self renderSample:kFingerprintSampleCount - 1];
    return;
  }
  __weak FnoxFingerprintView* weakSelf = self;
  self.timer = [NSTimer timerWithTimeInterval:1.0 / kFingerprintSampleRate
                                      repeats:YES
                                        block:^(NSTimer* timer) {
                                          FnoxFingerprintView* view = weakSelf;
                                          if (view == nil || view.window == nil) {
                                            [timer invalidate];
                                            return;
                                          }
                                          [view tickAnimation];
                                        }];
  [[NSRunLoop mainRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];
}
- (void)tickAnimation {
  const double elapsed = CACurrentMediaTime() - self.startedAt;
  const unsigned index = static_cast<unsigned>(std::max(0.0, elapsed) * kFingerprintSampleRate);
  [self renderSample:index];
  if (index >= kFingerprintSampleCount - 1) {
    [self.timer invalidate];
    self.timer = nil;
  }
}
- (void)viewWillMoveToWindow:(NSWindow*)window {
  if (window == nil) {
    [self.timer invalidate];
    self.timer = nil;
  }
  [super viewWillMoveToWindow:window];
}
@end
