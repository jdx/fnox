#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QColor>
#include <QDialog>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QStyleFactory>
#include <QSvgRenderer>
#include <QTimer>
#include <QVBoxLayout>
#include <QWindow>
#include <cstdlib>
#include <memory>
#include <string>

#include "authorization.h"
#include "theme.generated.h"

namespace {
QString preview_value(const char* name, const QString& fallback) {
  const QByteArray value = qgetenv(name);
  return value.isEmpty() ? fallback : QString::fromUtf8(value);
}

QColor theme_color(const uint32_t (&colors)[2], bool dark) {
  return QColor::fromRgb(colors[dark ? 1 : 0]);
}

class Preview final : public QDialog {
 public:
  explicit Preview(bool system_auth)
      : system_auth_(system_auth),
        auth_(fnox::portable::make_authorization(!system_auth)) {
    setWindowTitle("Fnox approval preview");
    setModal(true);
    setFixedWidth(390);
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(12);
    auto* top = new QHBoxLayout;
    auto* icon = new QLabel;
    QFile logo(QStringLiteral(":/fnox-preview/logo.svg"));
    QPixmap pixmap;
    if (logo.open(QIODevice::ReadOnly)) pixmap.loadFromData(logo.readAll());
    if (!pixmap.isNull())
      icon->setPixmap(
          pixmap.scaled(32, 32, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    top->addWidget(icon);
    auto* title = new QLabel("Approve credential access?");
    title->setStyleSheet("font-size: 18px; font-weight: 600");
    top->addWidget(title, 1);
    root->addLayout(top);

    const bool screenshot =
        qEnvironmentVariable("FNOX_PREVIEW_MODE") == "screenshot";
    QLabel* preview = new QLabel("PREVIEW");
    preview->setAlignment(Qt::AlignCenter);
    preview->setStyleSheet(
        "font-size: 10px; font-weight: bold; letter-spacing: 2px; padding: "
        "4px");
    preview->setVisible(!screenshot);
    root->addWidget(preview);
    fingerprint_ = new QLabel;
    fingerprint_->setAlignment(Qt::AlignCenter);
    fingerprint_->setAccessibleName("Fingerprint preview");
    root->addWidget(fingerprint_);
    const QString project_directory = preview_value(
        "FNOX_PREVIEW_PROJECT_DIRECTORY", QStringLiteral("/workspace/example"));
    const QString project_name = QFileInfo(project_directory).fileName();
    const QString credential_name =
        preview_value("FNOX_PREVIEW_CREDENTIAL_NAME", QStringLiteral("EXAMPLE_SECRET"));
    const QString credential_binding =
        QStringLiteral("project:%1/%2").arg(project_name, credential_name);
    const QString credential_source =
        preview_value("FNOX_PREVIEW_CREDENTIAL_SOURCE", QStringLiteral("Example provider"));
    const QString executable = preview_value(
        "FNOX_PREVIEW_EXECUTABLE", QStringLiteral("/usr/local/bin/example-command"));
    const QString command =
        preview_value("FNOX_PREVIEW_COMMAND", QStringLiteral("fnox exec -- ./example.sh"));
    auto* heading = new QLabel(QString("Allow agent to use %1?").arg(credential_name));
    heading->setStyleSheet("font-size: 16px; font-weight: 600");
    root->addWidget(heading);
    auto* body = new QLabel(QString("Source: %1 · %2\nProgram: %3\nCommand: %4\nProject: %5\n\n"
                                    "No credentials will be read.")
                                .arg(credential_source, credential_binding, executable, command,
                                     project_directory));
    body->setWordWrap(true);
    body->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(body);
    auto* details = new QPushButton("Copy details");
    details->setFlat(true);
    connect(details, &QPushButton::clicked, this, [credential_name, credential_binding,
                                                    executable, command, project_directory] {
      QGuiApplication::clipboard()->setText(
          QString("%1\n%2\n%3\n%4\n%5")
              .arg(credential_name, credential_binding, executable, command, project_directory));
    });
    root->addWidget(details, 0, Qt::AlignLeft);
    status_ = new QLabel(system_auth
                             ? "System verification is opt-in."
                             : "Press Shift+Return to simulate verification.");
    status_->setVisible(system_auth || !screenshot);
    status_->setWordWrap(true);
    root->addWidget(status_);
    auto* buttons = new QHBoxLayout;
    buttons->addStretch();
    auto* cancel = new QPushButton("Cancel");
    auto* approve =
        new QPushButton(system_auth ? "Verify" : "Simulate approval");
    cancel->setDefault(true);
    buttons->addWidget(cancel);
    buttons->addWidget(approve);
    root->addLayout(buttons);
    connect(cancel, &QPushButton::clicked, this, [this] {
      auth_->cancel();
      reject();
    });
    connect(approve, &QPushButton::clicked, this, [this] { begin_auth(); });
    approve_ = approve;
    cancel_ = cancel;
    apply_theme();
  }

  ~Preview() override { auth_->cancel(); }

  bool smoke() {
    if (system_auth_) return false;
    QTimer::singleShot(0, this, [this] { begin_auth(); });
    return exec() == QDialog::Accepted;
  }

 protected:
  void changeEvent(QEvent* event) override {
    QDialog::changeEvent(event);
    if (event->type() == QEvent::ApplicationPaletteChange) apply_theme();
  }
  void keyPressEvent(QKeyEvent* event) override {
    if (event->key() == Qt::Key_Escape) {
      auth_->cancel();
      reject();
      return;
    }
    if (!system_auth_ && event->key() == Qt::Key_Return &&
        event->modifiers().testFlag(Qt::ShiftModifier)) {
      begin_auth();
      return;
    }
    QDialog::keyPressEvent(event);
  }
  void closeEvent(QCloseEvent* event) override {
    auth_->cancel();
    QDialog::closeEvent(event);
  }

 private:
  void apply_theme() {
    const bool dark = palette().color(QPalette::Window).lightness() < 128;
    const QColor bg = palette().color(QPalette::Window);
    const QString text = theme_color(fnox::kThemeCancelText, dark).name();
    const QString fill =
        dark ? theme_color(fnox::kThemeResting, true).name() : "transparent";
    setStyleSheet(
        QString("QDialog { background: %1; color: %2; } QLabel { color: %2; } "
                "QPushButton { padding: 7px 13px; border-radius: 7px; border: "
                "1px solid %2; background: %3; color: %2; } "
                "QPushButton:hover, QPushButton:focus { border: 2px solid %4; "
                "padding: 6px 12px; } "
                "QPushButton:pressed { background: %2; color: %1; } "
                "QPushButton:disabled { color: %4; border-color: %4; }")
            .arg(bg.name(), text, fill,
                 theme_color(fnox::kThemeIncoming, dark).name()));
    if (!fingerprint_) return;
    QPixmap image(288, 288);
    image.fill(Qt::transparent);
    {
      QPainter painter(&image);
      painter.setRenderHint(QPainter::Antialiasing);
      if (finished_) {
        painter.setPen(QPen(theme_color(fnox::kThemeSuccess, dark), 7));
        painter.drawEllipse(QRectF(20, 20, 248, 248));
        QSvgRenderer renderer(QStringLiteral(":/fnox-preview/check.svg"));
        renderer.render(&painter, QRectF(55, 55, 178, 178));
      } else {
        QSvgRenderer renderer(QStringLiteral(":/fnox-preview/geometry.svg"));
        renderer.render(&painter);
      }
      painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
      painter.fillRect(
          image.rect(),
          theme_color(finished_ ? fnox::kThemeSuccess : fnox::kThemeResting,
                      dark));
    }
    image.setDevicePixelRatio(2);
    fingerprint_->setPixmap(image);
  }
  void show_success(const QString& message) {
    if (finished_) return;
    finished_ = true;
    fingerprint_->setAccessibleName(system_auth_ ? "User verified"
                                                 : "Simulated approval");
    apply_theme();
    status_->show();
    status_->setText(message);
    status_->setStyleSheet(
        QString("color: %1; font-weight: bold")
            .arg(
                theme_color(fnox::kThemeSuccess,
                            palette().color(QPalette::Window).lightness() < 128)
                    .name()));
    approve_->setEnabled(false);
    cancel_->setText("Close");
    disconnect(cancel_, nullptr, this, nullptr);
    connect(cancel_, &QPushButton::clicked, this, &QDialog::accept);
    QTimer::singleShot(900, this, &QDialog::accept);
  }
  void begin_auth() {
    if (finished_ || attempted_) return;
    attempted_ = true;
    approve_->setEnabled(false);
    status_->setText(
        system_auth_
            ? "Use Windows Hello or touch the enrolled fingerprint reader."
            : "Simulating approval…");
    status_->show();
    auth_->start([this, guard = QPointer<Preview>(this)](
                     fnox::portable::Result result, std::string message) {
      if (!guard || finished_) return;
      if (result == fnox::portable::Result::Verified)
        show_success(
            system_auth_
                ? "Verified by the operating system. No credentials were read."
                : "Approved (simulated) — no credentials were read.");
      else {
        status_->setText(QString::fromStdString(
            message.empty() ? "Verification was not completed." : message));
        approve_->setEnabled(false);
      }
    });
  }
  std::unique_ptr<fnox::portable::Authorization> auth_;
  bool system_auth_ = false;
  QLabel* status_{};
  QLabel* fingerprint_{};
  QPushButton* approve_{};
  QPushButton* cancel_{};
  bool finished_ = false;
  bool attempted_ = false;
};
}  // namespace

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  const QByteArray mode = qgetenv("FNOX_PREVIEW_AUTH");
  if (!mode.isEmpty() && mode != "simulate" && mode != "system") return 2;
  const bool system = mode == "system";
  const auto appearance = qEnvironmentVariable("FNOX_PREVIEW_APPEARANCE");
  if (appearance == "light" || appearance == "dark") {
    QPalette palette = app.palette();
    const bool dark = appearance == "dark";
    palette.setColor(QPalette::Window, QColor(dark ? "#171e28" : "#fcfbf8"));
    palette.setColor(QPalette::WindowText,
                     QColor(dark ? "#eeeee9" : "#191916"));
    app.setPalette(palette);
  }
  Preview preview(system);
  if (app.arguments().contains("--smoke-test"))
    return system ? 2 : (preview.smoke() ? 0 : 1);
  return preview.exec() == QDialog::Accepted ? 0 : 1;
}
