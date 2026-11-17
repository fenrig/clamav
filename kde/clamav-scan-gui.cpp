/* Native Qt6 scan dialog for the KDE ClamAV integration. */
#include <QApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QDir>
#include <QFrame>
#include <QFormLayout>
#include <QCloseEvent>
#include <QCheckBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QLocalSocket>
#include <QMessageBox>
#include <QProcess>
#include <QProgressBar>
#include <QPainter>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>
#include <QTextEdit>
#include <QTextCursor>
#include <QTimer>
#include <QLocale>
#include <QTranslator>
#include <QVBoxLayout>
#include <QDialog>
#include <QFileDialog>
#include <QFileSystemWatcher>
#include <QDesktopServices>
#include <QScrollArea>
#include <QScrollBar>
#include <QListWidget>
#include <QSplitter>
#include <QTabWidget>
#include <QUrl>
#include <QUuid>

#include "../quarantine/quarantine.h"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <unistd.h>
#include <utility>

namespace {

static int detectionLevel(const QString &detection)
{
    const QString name = detection.section(QStringLiteral(": "), -1).trimmed();
    if (name.startsWith(QStringLiteral("Eicar"), Qt::CaseInsensitive)) return 1;
    if (name.startsWith(QStringLiteral("PUA."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("PUP."), Qt::CaseInsensitive)) return 2;
    if (name.startsWith(QStringLiteral("Phishing."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("Heuristics."), Qt::CaseInsensitive)) return 3;
    return 4;
}

static QString detectionLevelLabel(int level)
{
    switch (level) {
    case 1: return QObject::tr("Test signature — harmless");
    case 2: return QObject::tr("Potentially unwanted");
    case 3: return QObject::tr("Suspicious content");
    default: return QObject::tr("Malware detection");
    }
}

static QColor detectionLevelColor(int level)
{
    switch (level) {
    case 1: return QColor(80, 170, 100);
    case 2: return QColor(220, 170, 30);
    case 3: return QColor(235, 125, 30);
    default: return QColor(210, 55, 65);
    }
}

class ScaledIconLabel final : public QLabel
{
public:
    using QLabel::QLabel;

    void setStatusIcon(const QIcon &icon)
    {
        icon_ = icon;
        if (!icon_.isNull())
            setText(QString());
        update();
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        if (icon_.isNull()) {
            QLabel::paintEvent(event);
            return;
        }
        QPainter painter(this);
        const int side = std::min(width(), height());
        const QPixmap pixmap = icon_.pixmap(QSize(side, side));
        painter.drawPixmap((width() - pixmap.width()) / 2,
                           (height() - pixmap.height()) / 2, pixmap);
    }

private:
    QIcon icon_;
};

static QString canonicalDetection(QString detection)
{
    detection = detection.trimmed();
    detection.remove(QRegularExpression(QStringLiteral("\\s+FOUND$"),
                                        QRegularExpression::CaseInsensitiveOption));
    const int separator = detection.lastIndexOf(QStringLiteral(": "));
    if (separator >= 0)
        detection = detection.mid(separator + 2).trimmed();
    return detection;
}

static QString lookupDetectionName(const QString &detection)
{
    QString name = canonicalDetection(detection);
    name.remove(QRegularExpression(QStringLiteral("^ClamAV\\s+fd\\[\\d+\\]:\\s*"),
                                   QRegularExpression::CaseInsensitiveOption));
    return name.trimmed();
}

struct Stats {
    int queue = 0;
    int live = 0;
    int idle = 0;
    int maximum = 0;
    double memory = 0.0;
    bool valid = false;
};

struct DetectionEntry {
    QString path;
    QString detection;
    QString sha256;
    QString quarantineId;
    bool handled = false;
    bool deleted = false;
};

struct ActivityEntry {
    QString path;
    QString detection;
};

QList<qint64> clamdPids()
{
    QList<qint64> pids;
    DIR *directory = opendir("/proc");
    if (!directory)
        return pids;
    while (const dirent *entry = readdir(directory)) {
        bool numeric = false;
        const qint64 pid = QByteArray(entry->d_name).toLongLong(&numeric);
        if (!numeric)
            continue;
        QFile comm(QStringLiteral("/proc/%1/comm").arg(pid));
        if (comm.open(QIODevice::ReadOnly) && comm.readAll().trimmed() == "clamd")
            pids << pid;
    }
    closedir(directory);
    return pids;
}

QStringList configuredSockets()
{
    QStringList files = {QStringLiteral("/etc/clamd.conf"), QStringLiteral("/etc/clamav/clamd.conf"),
        QStringLiteral("/etc/clamd.d/scan.conf")};
    QDir configDirectory(QStringLiteral("/etc/clamd.d"));
    for (const QString &file : configDirectory.entryList({QStringLiteral("*.conf")}, QDir::Files))
        files << configDirectory.filePath(file);
    QStringList sockets;
    const QRegularExpression expression(QStringLiteral("^\\s*LocalSocket\\s+(.+?)\\s*(?:#.*)?$"));
    for (const QString &path : std::as_const(files)) {
        QFile config(path);
        if (!config.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;
        while (!config.atEnd()) {
            const auto match = expression.match(QString::fromUtf8(config.readLine()));
            if (match.hasMatch() && !sockets.contains(match.captured(1)))
                sockets << match.captured(1);
        }
    }
    for (const QString &socket : {QStringLiteral("/run/clamav/clamd.sock"),
                                  QStringLiteral("/run/clamav/clamd.ctl"),
                                  QStringLiteral("/var/run/clamav/clamd.sock"),
                                  QStringLiteral("/var/run/clamav/clamd.ctl")})
        if (!sockets.contains(socket))
            sockets << socket;
    return sockets;
}

static QString auditLogPath(const QString &name)
{
    QString state = qEnvironmentVariable("XDG_STATE_HOME");
    if (state.isEmpty())
        state = QDir::home().filePath(QStringLiteral(".local/state"));
    return QDir(state).filePath(QStringLiteral("clamav/%1").arg(name));
}

static QString prettyAuditLog(const QString &path)
{
    const int lockFd = ::open(path.toLocal8Bit().constData(), O_RDONLY | O_CLOEXEC);
    if (lockFd < 0)
        return QObject::tr("No log entries yet.");
    if (flock(lockFd, LOCK_SH) != 0) {
        ::close(lockFd);
        return QObject::tr("The log is temporarily unavailable.");
    }
    QFile file(path);
    const QByteArray contents = file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    flock(lockFd, LOCK_UN);
    ::close(lockFd);
    if (contents.isEmpty())
        return QObject::tr("No log entries yet.");

    QStringList lines;
    for (const QByteArray &raw : contents.split('\n')) {
        if (raw.trimmed().isEmpty())
            continue;
        QJsonParseError error;
        const QJsonDocument document = QJsonDocument::fromJson(raw, &error);
        if (error.error != QJsonParseError::NoError || !document.isObject())
            continue;
        const QJsonObject record = document.object();
        const QDateTime timestamp = QDateTime::fromSecsSinceEpoch(
            static_cast<qint64>(record.value(QStringLiteral("time")).toDouble()));
        const QString action = record.value(QStringLiteral("action")).toString();
        const bool success = record.value(QStringLiteral("success")).toBool();
        lines << QStringLiteral("[%1] %2 · %3")
                     .arg(timestamp.toString(Qt::ISODate).replace(QLatin1Char('T'), QLatin1Char(' ')),
                          action,
                          success ? QObject::tr("completed") : QObject::tr("failed"));
        if (record.contains(QStringLiteral("source")))
            lines << QStringLiteral("  %1: %2").arg(QObject::tr("Source"), record.value(QStringLiteral("source")).toString());
        if (record.contains(QStringLiteral("component")))
            lines << QStringLiteral("  %1: %2").arg(QObject::tr("Component"), record.value(QStringLiteral("component")).toString());
        if (record.contains(QStringLiteral("detail"))) {
            QString detail = record.value(QStringLiteral("detail")).toString();
            const QRegularExpression scanIdExpression(QStringLiteral("^scan=([^;]+);?\\s*(.*)$"));
            const auto scanIdMatch = scanIdExpression.match(detail);
            if (scanIdMatch.hasMatch()) {
                lines << QStringLiteral("  %1: %2").arg(QObject::tr("Scan"), scanIdMatch.captured(1));
                detail = scanIdMatch.captured(2);
            }
            if (!detail.isEmpty())
                lines << QStringLiteral("  %1: %2").arg(QObject::tr("Details"), detail);
        }
        lines << QString();
    }
    return lines.isEmpty() ? QObject::tr("No readable log entries yet.") : lines.join(QLatin1Char('\n'));
}

Stats queryStats(QString &socketPath)
{
    if (socketPath.isEmpty()) {
        for (const QString &candidate : configuredSockets()) {
            if (QFileInfo::exists(candidate)) {
                socketPath = candidate;
                break;
            }
        }
    }
    if (socketPath.isEmpty())
        return {};

    QLocalSocket socket;
    socket.connectToServer(socketPath);
    if (!socket.waitForConnected(250)) {
        socketPath.clear();
        return {};
    }
    socket.write("nSTATS\n");
    socket.flush();
    QByteArray response;
    while (!response.contains("\nEND\n") && response.size() < 65536) {
        if (!socket.waitForReadyRead(250))
            break;
        response += socket.readAll();
    }

    Stats stats;
    const QRegularExpression queue(QStringLiteral("^QUEUE:\\s*(\\d+)\\s+items"), QRegularExpression::MultilineOption);
    const QRegularExpression threads(QStringLiteral("^THREADS:\\s+live\\s+(\\d+)\\s+idle\\s+(\\d+)\\s+max\\s+(\\d+)"), QRegularExpression::MultilineOption);
    const QRegularExpression memory(QStringLiteral("^MEMSTATS:.*?heap\\s+([\\d.]+)M.*?mmap\\s+([\\d.]+)M.*?pools_total\\s+([\\d.]+)M"), QRegularExpression::MultilineOption);
    auto match = queue.match(QString::fromUtf8(response));
    if (match.hasMatch())
        stats.queue = match.captured(1).toInt();
    match = threads.match(QString::fromUtf8(response));
    if (match.hasMatch()) {
        stats.live = match.captured(1).toInt();
        stats.idle = match.captured(2).toInt();
        stats.maximum = match.captured(3).toInt();
    }
    match = memory.match(QString::fromUtf8(response));
    if (match.hasMatch())
        stats.memory = match.captured(1).toDouble() + match.captured(2).toDouble() + match.captured(3).toDouble();
    stats.valid = queue.match(QString::fromUtf8(response)).hasMatch() || threads.match(QString::fromUtf8(response)).hasMatch();
    return stats;
}

class ScanDialog final : public QDialog
{
public:
    ScanDialog(const QString &scanner, const QStringList &paths, bool quarantine)
        : scanner_(scanner), paths_(paths), quarantine_(quarantine),
          scanId_(QUuid::createUuid().toString(QUuid::WithoutBraces)),
          started_(std::chrono::steady_clock::now())
    {
        setWindowTitle(tr("ClamAV virus scan"));
        setWindowIcon(QIcon::fromTheme(QStringLiteral("clamav")));
        resize(1100, 700);
        setMinimumSize(720, 500);

        auto *layout = new QVBoxLayout(this);
        auto *headingRow = new QHBoxLayout;
        statusIcon_ = new QLabel(this);
        statusIcon_->setFixedSize(36, 36);
        setStatusIcon(QColor(QStringLiteral("#3daee9")), QChar());
        headingRow->addWidget(statusIcon_);
        heading_ = new QLabel(quarantine_ ? tr("Scanning and protecting with ClamAV")
                                           : tr("Scanning with ClamAV"), this);
        heading_->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: 600;"));
        headingRow->addWidget(heading_);
        headingRow->addStretch();
        layout->addLayout(headingRow);

        tabs_ = new QTabWidget(this);
        tabs_->setTabPosition(QTabWidget::West);
        auto *scanPage = new QWidget(tabs_);
        scanPage_ = scanPage;
        auto *scanLayout = new QVBoxLayout(scanPage);

        summary_ = new QLabel(tr("Preparing scan…"), this);
        summary_->setStyleSheet(QStringLiteral("font-size: 15px; font-weight: 600; color: palette(window-text);"));
        layout->addWidget(summary_);
        statusCard_ = new QFrame(this);
        statusCard_->setObjectName(QStringLiteral("scanStatusCard"));
        auto *statusLayout = new QHBoxLayout(statusCard_);
        statusLayout->setContentsMargins(16, 12, 16, 12);
        auto *statusText = new QVBoxLayout;
        statusCardTitle_ = new QLabel(statusCard_);
        statusCardTitle_->setStyleSheet(QStringLiteral("font-size: 16px; font-weight: 600; color: palette(window-text);"));
        statusCardDetails_ = new QLabel(statusCard_);
        statusCardDetails_->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        statusCardDetails_->setWordWrap(true);
        statusText->addWidget(statusCardTitle_);
        statusText->addWidget(statusCardDetails_);
        statusLayout->addLayout(statusText, 1);
        stopStatusButton_ = new QPushButton(tr("Stop scan"), statusCard_);
        stopStatusButton_->setIcon(QIcon::fromTheme(QStringLiteral("media-playback-stop"),
                                                     QIcon::fromTheme(QStringLiteral("process-stop"))));
        stopStatusButton_->setVisible(false);
        statusLayout->addSpacing(8);
        statusLayout->addWidget(stopStatusButton_);
        openQuarantineButton_ = new QPushButton(tr("Open quarantine"), statusCard_);
        openQuarantineButton_->setIcon(QIcon::fromTheme(QStringLiteral("clamav-quarantine"),
                                                         QIcon::fromTheme(QStringLiteral("folder-open"))));
        statusLayout->addSpacing(4);
        statusLayout->addWidget(openQuarantineButton_);
        connect(stopStatusButton_, &QPushButton::clicked, this, [this] { cancelOrClose(); });
        connect(openQuarantineButton_, &QPushButton::clicked, this, [this] {
            if (!QProcess::startDetached(QStringLiteral("clamav-quarantine-gui")))
                QMessageBox::warning(this, tr("ClamAV"), tr("The quarantine manager could not be opened."));
        });
        layout->addWidget(statusCard_);
        pulseTimer_.setInterval(700);
        connect(&pulseTimer_, &QTimer::timeout, this, [this] {
            pulseOn_ = !pulseOn_;
            updateStatusCard();
        });
        pulseTimer_.start();
        updateStatusCard();
        targetSummary_ = new QLabel(this);
        targetSummary_->setText(targetDescription());
        targetSummary_->setStyleSheet(QStringLiteral("color: palette(mid);"));
        targetSummary_->setWordWrap(true);
        targetSummary_->hide();

        tabs_->addTab(scanPage, tr("Scan"));
        layout->addWidget(tabs_, 1);

        auto *targetsPanel = new QFrame(tabs_);
        targetsPanel->setObjectName(QStringLiteral("scanTargetsPanel"));
        auto *targetsLayout = new QVBoxLayout(targetsPanel);
        auto *targetsTitle = new QLabel(tr("Scan locations and files"), targetsPanel);
        targetsTitle->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: 600;"));
        targetsLayout->addWidget(targetsTitle);
        auto *targetsInfo = new QLabel(tr("These targets came from the command line. You can change them after the scan finishes and run the scan again."), targetsPanel);
        targetsInfo->setWordWrap(true);
        targetsInfo->setStyleSheet(QStringLiteral("color: palette(mid);"));
        targetsLayout->addWidget(targetsInfo);
        pathsList_ = new QListWidget(targetsPanel);
        pathsList_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        const auto addPathItem = [this](const QString &path) {
            auto *item = new QListWidgetItem(path, pathsList_);
            const bool folder = QFileInfo(path).isDir();
            item->setIcon(QIcon::fromTheme(folder ? QStringLiteral("folder")
                                                  : QStringLiteral("text-x-generic"),
                                           QIcon::fromTheme(folder ? QStringLiteral("folder-open")
                                                                    : QStringLiteral("document-open"))));
            item->setToolTip(folder ? tr("Folder to scan") : tr("File to scan"));
        };
        for (const QString &path : std::as_const(paths_))
            addPathItem(path);
        targetsLayout->addWidget(pathsList_, 1);
        auto *targetButtons = new QHBoxLayout;
        addFilesButton_ = new QPushButton(tr("Add files…"), targetsPanel);
        addFolderButton_ = new QPushButton(tr("Add folder…"), targetsPanel);
        removePathsButton_ = new QPushButton(tr("Remove selected"), targetsPanel);
        clearPathsButton_ = new QPushButton(tr("Clear"), targetsPanel);
        rescanButton_ = new QPushButton(tr("Scan"), targetsPanel);
        addFilesButton_->setIcon(QIcon::fromTheme(QStringLiteral("document-open")));
        addFolderButton_->setIcon(QIcon::fromTheme(QStringLiteral("folder-open")));
        removePathsButton_->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete")));
        rescanButton_->setIcon(QIcon::fromTheme(QStringLiteral("view-refresh")));
        targetButtons->addWidget(addFilesButton_);
        targetButtons->addWidget(addFolderButton_);
        targetButtons->addWidget(removePathsButton_);
        targetButtons->addWidget(clearPathsButton_);
        targetButtons->addStretch();
        targetButtons->addWidget(rescanButton_);
        targetsLayout->addLayout(targetButtons);
        tabs_->insertTab(0, targetsPanel, tr("Locations"));
        targetsPanel_ = targetsPanel;
        connect(addFilesButton_, &QPushButton::clicked, this, [this, addPathItem] {
            const QStringList selected = QFileDialog::getOpenFileNames(this, tr("Choose files to scan"));
            for (const QString &path : selected)
                if (!paths_.contains(path)) {
                    paths_ << path;
                    addPathItem(path);
                }
            targetSummary_->setText(targetDescription());
        });
        connect(addFolderButton_, &QPushButton::clicked, this, [this, addPathItem] {
            const QString path = QFileDialog::getExistingDirectory(this, tr("Choose a folder to scan"));
            if (!path.isEmpty() && !paths_.contains(path)) {
                paths_ << path;
                addPathItem(path);
                targetSummary_->setText(targetDescription());
            }
        });
        connect(removePathsButton_, &QPushButton::clicked, this, [this] {
            const auto rows = pathsList_->selectionModel()->selectedRows();
            QStringList paths;
            for (int row = 0; row < pathsList_->count(); ++row)
                if (!rows.contains(pathsList_->model()->index(row, 0)))
                    paths << pathsList_->item(row)->text();
            paths_ = paths;
            qDeleteAll(pathsList_->selectedItems());
            targetSummary_->setText(targetDescription());
        });
        connect(clearPathsButton_, &QPushButton::clicked, this, [this] {
            paths_.clear();
            pathsList_->clear();
            targetSummary_->setText(targetDescription());
        });
        connect(rescanButton_, &QPushButton::clicked, this, [this] {
            if (paths_.isEmpty()) {
                QMessageBox::warning(this, tr("ClamAV"), tr("Add at least one file or folder before scanning."));
                return;
            }
            startScanProcess();
        });

        auto *cards = new QHBoxLayout;
        queueStatus_ = addCard(cards, tr("Queue"), tr("Waiting for clamd…"), &queueMeter_);
        cpuStatus_ = addCard(cards, tr("CPU"), tr("Waiting for clamd…"), &cpuMeter_);
        scanLayout->addLayout(cards);

        progress_ = new QProgressBar(this);
        progress_->setRange(0, 0);
        progress_->setTextVisible(true);
        progress_->setFormat(tr("Scanning…"));
        scanLayout->addWidget(progress_);
        currentFileLabel_ = new QLabel(tr("Current file: preparing…"), this);
        currentFileLabel_->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        currentFileLabel_->setWordWrap(false);
        scanLayout->addWidget(currentFileLabel_);
        auto *activity = new QGroupBox(tr("Scan activity"), this);
        auto *activityLayout = new QVBoxLayout(activity);
        activityList_ = new QListWidget(activity);
        activityList_->setFrameShape(QFrame::NoFrame);
        activityList_->setWordWrap(true);
        activityList_->setAlternatingRowColors(false);
        activitySummary_ = new QLabel(tr("No files scanned yet."), activity);
        activitySummary_->setStyleSheet(QStringLiteral("font-weight: 600; color: palette(mid);"));
        activitySummary_->setWordWrap(true);
        activityLayout->addWidget(activitySummary_);
        activityLayout->addWidget(activityList_);
        scanLayout->addWidget(activity, 1);

        auto *buttons = new QHBoxLayout;
        buttons->addStretch();
        quarantineCheckBox_ = new QCheckBox(tr("Quarantine detected files when the scan finishes"), this);
        quarantineCheckBox_->setChecked(quarantine_);
        quarantineCheckBox_->setEnabled(!quarantine_);
        buttons->addWidget(quarantineCheckBox_);
        quarantineButton_ = new QPushButton(tr("Quarantine detected files"), this);
        quarantineButton_->setIcon(QIcon::fromTheme(QStringLiteral("clamav-quarantine"),
                                                     QIcon::fromTheme(QStringLiteral("security-high"))));
        quarantineButton_->setVisible(!quarantine_);
        quarantineButton_->setEnabled(false);
        connect(quarantineButton_, &QPushButton::clicked, this, [this] {
            quarantineDetectedFiles();
        });
        buttons->addWidget(quarantineButton_);
        pauseButton_ = new QPushButton(tr("Pause scan"), this);
        pauseButton_->setIcon(QIcon::fromTheme(QStringLiteral("media-playback-pause")));
        pauseButton_->setEnabled(false);
        connect(pauseButton_, &QPushButton::clicked, this, [this] { pauseOrResumeScan(); });
        buttons->addWidget(pauseButton_);
        action_ = new QPushButton(tr("Stop scan"), this);
        connect(action_, &QPushButton::clicked, this, [this] { cancelOrClose(); });
        buttons->addWidget(action_);
        scanLayout->addLayout(buttons);

        process_ = new QProcess(this);
        connect(process_, &QProcess::readyReadStandardOutput, this, [this] { readOutput(); });
        connect(process_, &QProcess::readyReadStandardError, this, [this] { readOutput(); });
        connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int code, QProcess::ExitStatus) { scanFinished(code); });
        connect(&metricsTimer_, &QTimer::timeout, this, [this] { updateMetrics(); });
        metricsTimer_.start(30000);
        connect(&statsTimer_, &QTimer::timeout, this, [this] { updateQueue(); });
        statsTimer_.start(30000);
        updateQueue();
        fileDisplayTimer_.setInterval(150);
        connect(&fileDisplayTimer_, &QTimer::timeout, this, [this] {
            if (!currentFile_.isEmpty()) {
                const QString text = tr("Current file: %1").arg(QDir::toNativeSeparators(currentFile_));
                if (currentFileLabel_->text() != text)
                    currentFileLabel_->setText(text);
                if (activityList_ && activityList_->isVisible()) {
                    QScrollBar *scrollBar = activityList_->verticalScrollBar();
                    if (scrollBar->value() >= scrollBar->maximum() - 2)
                        activityList_->scrollToBottom();
                }
            }
        });
        fileDisplayTimer_.start();

        detectionsPanel_ = new QFrame(tabs_);
        detectionsPanel_->setObjectName(QStringLiteral("detectionsPanel"));
        detectionsPanel_->setStyleSheet(QStringLiteral(
            "QFrame#detectionsPanel { background: palette(window); border: 1px solid palette(mid); border-radius: 8px; }"));
        auto *panelLayout = new QVBoxLayout(detectionsPanel_);
        auto *panelHeader = new QHBoxLayout;
        auto *panelTitle = new QLabel(tr("Detections found so far"), detectionsPanel_);
        panelTitle->setStyleSheet(QStringLiteral("font-weight: 600;"));
        panelHeader->addWidget(panelTitle);
        panelHeader->addStretch();
        panelLayout->addLayout(panelHeader);
        auto *splitter = new QSplitter(Qt::Horizontal, detectionsPanel_);
        detectionsList_ = new QListWidget(splitter);
        detectionsList_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        detectionsList_->setFrameShape(QFrame::NoFrame);
        splitter->addWidget(detectionsList_);

        detailsPanel_ = new QFrame(splitter);
        detailsPanel_->setFrameShape(QFrame::StyledPanel);
        auto *detailsLayout = new QVBoxLayout(detailsPanel_);
        detailEmptyState_ = new QLabel(detailsPanel_);
        detailEmptyState_->setObjectName(QStringLiteral("scanDetailEmptyState"));
        detailEmptyState_->setTextFormat(Qt::RichText);
        detailEmptyState_->setAlignment(Qt::AlignCenter);
        detailEmptyState_->setWordWrap(true);
        detailEmptyState_->setText(tr("<h2>Nothing selected</h2>"
                                      "<p>Select an infection to view its severity, source, hash, and handling status.</p>"));
        detailEmptyState_->setStyleSheet(QStringLiteral(
            "QLabel#scanDetailEmptyState { font-size: 16px; color: palette(window-text); padding: 32px; }"));
        detailsLayout->addWidget(detailEmptyState_, 1);
        detailContent_ = new QWidget(detailsPanel_);
        auto *detailContentLayout = new QVBoxLayout(detailContent_);
        detailContentLayout->setContentsMargins(0, 0, 0, 0);
        detailTitle_ = new QLabel(tr("Detection details"), detailContent_);
        detailTitle_->setStyleSheet(QStringLiteral("font-size: 20px; font-weight: 600; padding-bottom: 4px;"));
        detailContentLayout->addWidget(detailTitle_);
        auto *detailForm = new QFormLayout;
        detailForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
        detailForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        detailDetection_ = new QLabel(detailContent_);
        detailDetection_->setWordWrap(true);
        detailDetection_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        detailSeverity_ = new QLabel(detailsPanel_);
        detailSeverity_->setStyleSheet(QStringLiteral("font-weight: 600;"));
        detailForm->addRow(tr("Detection:"), detailDetection_);
        detailPath_ = new QLabel(detailContent_);
        detailPath_->setWordWrap(true);
        detailPath_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        detailForm->addRow(tr("Source path:"), detailPath_);
        detailHash_ = new QLabel(detailContent_);
        detailHash_->setWordWrap(true);
        detailHash_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        detailHash_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        detailForm->addRow(tr("SHA-256:"), detailHash_);
        detailForm->addRow(tr("Severity:"), detailSeverity_);
        detailContentLayout->addLayout(detailForm);
        auto *summaryCard = new QFrame(detailContent_);
        summaryCard->setObjectName(QStringLiteral("scanSummaryCard"));
        auto *summaryLayout = new QVBoxLayout(summaryCard);
        auto *summaryTitle = new QLabel(tr("What this means"), summaryCard);
        summaryTitle->setStyleSheet(QStringLiteral("font-weight: 600;"));
        summaryLayout->addWidget(summaryTitle);
        detailMeter_ = new QProgressBar(detailsPanel_);
        detailMeter_->setRange(0, 4);
        detailMeter_->setTextVisible(false);
        detailMeter_->setFixedHeight(8);
        summaryLayout->addWidget(detailMeter_);
        detailContentLayout->addWidget(summaryCard);
        detailStatus_ = new QLabel(detailsPanel_);
        detailStatus_->setWordWrap(true);
        detailContentLayout->addWidget(detailStatus_);
        detailStatusIcon_ = new ScaledIconLabel(detailContent_);
        detailStatusIcon_->setMinimumSize(48, 48);
        detailStatusIcon_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        detailStatusIcon_->setAlignment(Qt::AlignCenter);
        detailContentLayout->addWidget(detailStatusIcon_, 1);
        auto *lookupActions = new QVBoxLayout;
        lookupButton_ = new QPushButton(tr("Look up on DuckDuckGo"), detailContent_);
        virusTotalButton_ = new QPushButton(tr("Look up on VirusTotal"), detailContent_);
        lookupButton_->setIcon(QIcon::fromTheme(QStringLiteral("system-search"),
                                                QIcon::fromTheme(QStringLiteral("search"))));
        virusTotalButton_->setIcon(QIcon::fromTheme(QStringLiteral("applications-internet"),
                                                     QIcon::fromTheme(QStringLiteral("internet-services"))));
        lookupActions->addWidget(lookupButton_);
        lookupActions->addWidget(virusTotalButton_);
        detailContentLayout->addLayout(lookupActions);
        detailsLayout->addWidget(detailContent_, 1);
        detailContent_->setVisible(false);
        detailsLayout->addStretch();
        auto *actionBar = new QFrame(detectionsPanel_);
        actionBar->setObjectName(QStringLiteral("scanDetailActionBar"));
        auto *detailActions = new QVBoxLayout(actionBar);
        detailActions->setContentsMargins(10, 8, 10, 8);
        auto *actionHeader = new QHBoxLayout;
        auto *actionLabel = new QLabel(tr("Actions for selected detection"), actionBar);
        actionLabel->setStyleSheet(QStringLiteral("font-weight: 600;"));
        actionHeader->addWidget(actionLabel);
        actionHeader->addStretch();
        detailsToggleButton_ = new QPushButton(tr("Hide details"), actionBar);
        actionHeader->addWidget(detailsToggleButton_);
        detailActions->addLayout(actionHeader);
        detailQuarantineButton_ = new QPushButton(tr("Quarantine"), detailsPanel_);
        detailDeleteButton_ = new QPushButton(tr("Delete permanently"), detailsPanel_);
        detailQuarantineAllButton_ = new QPushButton(tr("Quarantine all"), actionBar);
        detailDeleteAllButton_ = new QPushButton(tr("Delete all"), actionBar);
        detailQuarantineButton_->setIcon(QIcon::fromTheme(QStringLiteral("security-high"),
                                                           QIcon::fromTheme(QStringLiteral("folder-locked"))));
        detailDeleteButton_->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete"),
                                                       QIcon::fromTheme(QStringLiteral("delete"))));
        detailQuarantineAllButton_->setIcon(QIcon::fromTheme(QStringLiteral("security-high"),
                                                              QIcon::fromTheme(QStringLiteral("folder-locked"))));
        detailDeleteAllButton_->setIcon(QIcon::fromTheme(QStringLiteral("trash-empty"),
                                                          QIcon::fromTheme(QStringLiteral("edit-delete"))));
        auto *selectedActions = new QHBoxLayout;
        selectedActions->addWidget(detailQuarantineButton_);
        selectedActions->addWidget(detailDeleteButton_);
        detailActions->addLayout(selectedActions);
        auto *bulkActions = new QHBoxLayout;
        auto *bulkLabel = new QLabel(tr("All detections"), actionBar);
        bulkLabel->setStyleSheet(QStringLiteral("font-weight: 600;"));
        bulkActions->addWidget(bulkLabel);
        bulkActions->addStretch();
        bulkActions->addWidget(detailQuarantineAllButton_);
        bulkActions->addWidget(detailDeleteAllButton_);
        detailActions->addLayout(bulkActions);
        splitter->addWidget(detailsPanel_);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        splitter->setCollapsible(1, true);
        auto *resultsBody = new QFrame(detectionsPanel_);
        resultsBody->setObjectName(QStringLiteral("scanResultsBody"));
        resultsBody->setStyleSheet(QStringLiteral(
            "QFrame#scanResultsBody { background: palette(base); border: 1px solid palette(mid); border-radius: 8px; }"));
        auto *resultsBodyLayout = new QVBoxLayout(resultsBody);
        resultsBodyLayout->setContentsMargins(1, 1, 1, 1);
        resultsBodyLayout->addWidget(splitter);
        panelLayout->addWidget(resultsBody, 1);
        panelLayout->addWidget(actionBar);
        detailsPanel_->setStyleSheet(QStringLiteral(
            "QFrame#scanSummaryCard { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#scanSummaryCard QLabel { border: none; background: transparent; }"
            "QFrame#scanDetailActionBar { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#scanDetailActionBar QLabel { border: none; background: transparent; }"));
        tabs_->addTab(detectionsPanel_, tr("Results (0)"));
        auto *logPage = new QWidget(tabs_);
        auto *logLayout = new QVBoxLayout(logPage);
        auto *logHeader = new QHBoxLayout;
        auto *logTitle = new QLabel(tr("Scan log"), logPage);
        logTitle->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: 600;"));
        logHeader->addWidget(logTitle);
        logHeader->addStretch();
        logFilter_ = new QLineEdit(logPage);
        logFilter_->setPlaceholderText(tr("Filter log…"));
        logFilter_->setClearButtonEnabled(true);
        logFilter_->setMaximumWidth(280);
        logHeader->addWidget(logFilter_);
        logRefreshButton_ = new QPushButton(tr("Oldest first"), logPage);
        logRefreshButton_->setIcon(QIcon::fromTheme(QStringLiteral("view-sort-ascending"),
                                                     QIcon::fromTheme(QStringLiteral("sort-ascending"))));
        logHeader->addWidget(logRefreshButton_);
        logLayout->addLayout(logHeader);
        logView_ = new QListWidget(logPage);
        logView_->setFrameShape(QFrame::NoFrame);
        logView_->setSelectionMode(QAbstractItemView::NoSelection);
        logLayout->addWidget(logView_, 1);
        tabs_->addTab(logPage, tr("Log"));
        logPath_ = auditLogPath(QStringLiteral("scan.log"));
        logWatcher_ = new QFileSystemWatcher(this);
        connect(logWatcher_, &QFileSystemWatcher::fileChanged, this, [this] {
            refreshLog();
            if (QFileInfo::exists(logPath_) && !logWatcher_->files().contains(logPath_))
                logWatcher_->addPath(logPath_);
        });
        connect(logWatcher_, &QFileSystemWatcher::directoryChanged, this, [this] {
            refreshLog();
            if (QFileInfo::exists(logPath_) && !logWatcher_->files().contains(logPath_))
                logWatcher_->addPath(logPath_);
        });
        logRefreshTimer_.setInterval(5000);
        connect(&logRefreshTimer_, &QTimer::timeout, this, [this] { refreshLog(); });
        connect(logFilter_, &QLineEdit::textChanged, this, [this] { refreshLog(); });
        connect(logRefreshButton_, &QPushButton::clicked, this, [this] {
            logNewestFirst_ = !logNewestFirst_;
            logRefreshButton_->setText(logNewestFirst_ ? tr("Oldest first") : tr("Newest first"));
            refreshLog();
        });
        connect(tabs_, &QTabWidget::currentChanged, this, [this, logPage](int) {
            setLogMonitoring(tabs_->currentWidget() == logPage);
            if (tabs_->currentWidget() == scanPage_)
                refreshActivityList();
            if (tabs_->currentWidget() == detectionsPanel_)
                refreshDetectionsPanel();
        });
        connect(detectionsList_, &QListWidget::currentRowChanged, this,
                [this](int) { updateSelectedDetection(); });
        connect(detectionsList_, &QListWidget::itemSelectionChanged, this,
                [this] { updateSelectedDetection(); });
        connect(lookupButton_, &QPushButton::clicked, this, [this] { lookupSelectedDetection(false); });
        connect(virusTotalButton_, &QPushButton::clicked, this, [this] { lookupSelectedDetection(true); });
        connect(detailQuarantineButton_, &QPushButton::clicked, this,
                [this] { quarantineSelectedDetection(); });
        connect(detailDeleteButton_, &QPushButton::clicked, this,
                [this] { deleteSelectedDetection(); });
        connect(detailQuarantineAllButton_, &QPushButton::clicked, this,
                [this] { quarantineDetectedFiles(); });
        connect(detailDeleteAllButton_, &QPushButton::clicked, this,
                [this] { deleteAllDetections(); });
        connect(detailsToggleButton_, &QPushButton::clicked, this, [this] {
            const bool visible = detailsPanel_->isVisible();
            detailsPanel_->setVisible(!visible);
            detailsToggleButton_->setText(visible ? tr("Show details") : tr("Hide details"));
        });
        if (paths_.isEmpty()) {
            waitingForTargets_ = true;
            pulseTimer_.stop();
            metricsTimer_.stop();
            statsTimer_.stop();
            fileDisplayTimer_.stop();
            tabs_->setCurrentWidget(targetsPanel_);
            action_->setText(tr("Close"));
            setTargetEditingEnabled(true);
            updateStatusCard();
        } else {
            startScanProcess();
        }
    }

private:
    void refreshActivityList()
    {
        if (!activityList_)
            return;
        activityList_->setUpdatesEnabled(false);
        activityList_->clear();
        for (int index = 0; index < activityEntries_.size(); ++index) {
            activityList_->addItem(QString());
            updateActivityItem(index);
        }
        activityList_->setUpdatesEnabled(true);
        activityList_->viewport()->update();
        updateActivitySummary();
        if (currentActivityIndex_ >= 0 && currentActivityIndex_ < activityList_->count())
            activityList_->scrollToItem(activityList_->item(currentActivityIndex_));
    }

    void setLogMonitoring(bool enabled)
    {
        if (!enabled) {
            logRefreshTimer_.stop();
            for (const QString &path : logWatcher_->files())
                logWatcher_->removePath(path);
            for (const QString &path : logWatcher_->directories())
                logWatcher_->removePath(path);
            return;
        }
        const QString logDirectory = QFileInfo(logPath_).absolutePath();
        if (QFileInfo::exists(logDirectory))
            logWatcher_->addPath(logDirectory);
        if (QFileInfo::exists(logPath_))
            logWatcher_->addPath(logPath_);
        refreshLog();
        logRefreshTimer_.start();
    }

    void refreshLog()
    {
        if (!logView_)
            return;
        logView_->clear();
        const QString text = prettyAuditLog(logPath_);
        if (text.startsWith(tr("No log"))) {
            auto *item = new QListWidgetItem(logView_);
            auto *empty = new QLabel(text, logView_);
            empty->setAlignment(Qt::AlignCenter);
            empty->setStyleSheet(QStringLiteral("color: palette(mid); padding: 32px;"));
            item->setSizeHint(QSize(0, 90));
            logView_->setItemWidget(item, empty);
            return;
        }
        QStringList blocks = text.split(QStringLiteral("\n\n"), Qt::SkipEmptyParts);
        if (!logFilter_->text().trimmed().isEmpty()) {
            const QString filter = logFilter_->text().trimmed();
            blocks.erase(std::remove_if(blocks.begin(), blocks.end(), [&filter](const QString &block) {
                return !block.contains(filter, Qt::CaseInsensitive);
            }), blocks.end());
        }
        QHash<QString, QColor> scanColors;
        QHash<QString, QColor> scanFinalColors;
        const QList<QColor> baseColors = {QColor("#3daee9"), QColor("#d9a441"), QColor("#9b59b6")};
        int nextColor = 0;
        for (const QString &block : blocks) {
            const QStringList lines = block.split(QLatin1Char('\n'));
            QString scanId;
            for (const QString &line : lines)
                if (line.startsWith(QStringLiteral("  Scan: ")))
                    scanId = line.mid(QStringLiteral("  Scan: ").size());
            if (!scanId.isEmpty() && !scanColors.contains(scanId))
                scanColors.insert(scanId, baseColors.at(nextColor++ % baseColors.size()));
            if (!scanId.isEmpty() && lines.first().contains(QStringLiteral("] scan-close "))) {
                scanFinalColors.insert(scanId, block.contains(QStringLiteral("all detections handled"))
                    ? QColor("#50aa64") : QColor("#da4453"));
            }
        }
        if (logNewestFirst_)
            std::reverse(blocks.begin(), blocks.end());
        for (const QString &block : blocks) {
            const QStringList lines = block.split(QLatin1Char('\n'));
            if (lines.isEmpty())
                continue;
            QString scanId;
            for (const QString &line : lines)
                if (line.startsWith(QStringLiteral("  Scan: ")))
                    scanId = line.mid(QStringLiteral("  Scan: ").size());
            const QColor color = scanFinalColors.value(scanId, scanColors.value(scanId, QColor("#3daee9")));
            auto *item = new QListWidgetItem(logView_);
            auto *card = new QFrame(logView_);
            card->setStyleSheet(QStringLiteral(
                "QFrame { background: palette(alternate-base); border: 1px solid %1; border-left: 5px solid %1; border-radius: 8px; }"
                "QLabel { border: none; background: transparent; }")
                .arg(color.name()));
            auto *layout = new QVBoxLayout(card);
            layout->setContentsMargins(12, 9, 12, 9);
            auto *header = new QLabel(lines.first(), card);
            header->setStyleSheet(QStringLiteral("font-weight: 700; font-size: 14px;"));
            layout->addWidget(header);
            if (lines.size() > 1) {
                auto *body = new QLabel(lines.mid(1).join(QLatin1Char('\n')), card);
                body->setWordWrap(true);
                body->setTextInteractionFlags(Qt::TextSelectableByMouse);
                body->setStyleSheet(QStringLiteral("font-family: monospace; color: palette(window-text);"));
                layout->addWidget(body);
            }
            item->setSizeHint(QSize(0, 20 + card->sizeHint().height()));
            logView_->setItemWidget(item, card);
        }
    }

    void writeAudit(const QString &action, const QString &source, const QString &detail,
                    bool success = true)
    {
        const QByteArray actionBytes = action.toUtf8();
        const QByteArray sourceBytes = source.toUtf8();
        const QString loggedDetail = QStringLiteral("scan=%1; %2").arg(scanId_, detail);
        const QByteArray detailBytes = loggedDetail.toUtf8();
        clamav_scan_audit(actionBytes.constData(), "plasma",
                          source.isEmpty() ? nullptr : sourceBytes.constData(),
                          detail.isEmpty() ? nullptr : detailBytes.constData(), success ? 1 : 0);
    }

    void setTargetEditingEnabled(bool enabled)
    {
        for (QWidget *widget : {static_cast<QWidget *>(addFilesButton_),
                                static_cast<QWidget *>(addFolderButton_),
                                static_cast<QWidget *>(removePathsButton_),
                                static_cast<QWidget *>(clearPathsButton_)})
            if (widget)
                widget->setEnabled(enabled);
        rescanButton_->setEnabled(enabled && (finished_ || waitingForTargets_) && !paths_.isEmpty());
    }

    void startScanProcess()
    {
        if (paths_.isEmpty() || process_->state() != QProcess::NotRunning)
            return;
        finished_ = false;
        waitingForTargets_ = false;
        cancelled_ = false;
        paused_ = false;
        closeLogged_ = false;
        scanId_ = QUuid::createUuid().toString(QUuid::WithoutBraces);
        cpuSample_ = -1;
        sampleTime_ = 0.0;
        cpuSeconds_ = 0.0;
        cpuPeak_ = 0.0;
        infectionDetected_ = false;
        infectionDetected_ = !detectedFiles_.isEmpty();
        currentDetectionKeys_.clear();
        scanHashes_.clear();
        activityList_->clear();
        activityEntries_.clear();
        activityDetectionCount_ = 0;
        currentActivityIndex_ = -1;
        updateActivitySummary();
        refreshDetectionsIfVisible();
        tabs_->setCurrentWidget(scanPage_);
        summary_->setText(tr("Preparing scan…"));
        currentFileLabel_->setText(tr("Current file: preparing…"));
        progress_->setRange(0, 0);
        progress_->setFormat(tr("Scanning…"));
        action_->setEnabled(true);
        action_->setText(tr("Stop scan"));
        pauseButton_->setText(tr("Pause scan"));
        pauseButton_->setIcon(QIcon::fromTheme(QStringLiteral("media-playback-pause")));
        pauseButton_->setEnabled(true);
        setStatusIcon(QColor(QStringLiteral("#3daee9")), QChar());
        started_ = std::chrono::steady_clock::now();
        pulseOn_ = false;
        pulseTimer_.start();
        metricsTimer_.start(30000);
        statsTimer_.start(30000);
        fileDisplayTimer_.start();
        setTargetEditingEnabled(false);
        updateStatusCard();
        QStringList arguments{QStringLiteral("--scan-only")};
        arguments += paths_;
        process_->start(scanner_, arguments);
        pids_ = {process_->processId()};
        cpuTarget_ = clamdPids().isEmpty() ? tr("Scanner") : tr("ClamAV");
        updateMetrics();
        updateQueue();
        writeAudit(QStringLiteral("scan-start"), QString(),
                   QStringLiteral("scanner=%1; targets=%2").arg(scanner_).arg(paths_.size()));
    }

    void updateStatusCard()
    {
        const bool running = !finished_;
        const int pending = std::count_if(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                          [](const DetectionEntry &entry) {
                                              return !entry.handled && !entry.deleted;
                                          });
        const bool allHandled = !running && infectionDetected_ && !detectedFiles_.isEmpty() && pending == 0;
        const QColor blue(60, 145, 220);
        const QColor red(210, 55, 65);
        const QColor green(80, 170, 100);
        QColor color = green;
        QString title = tr("Scan complete");
        QString details = tr("No threats were found.");
        if (waitingForTargets_) {
            color = blue;
            title = tr("Choose scan locations");
            details = tr("Add at least one file or folder, then start the scan.");
        } else if (running && paused_) {
            color = QColor(243, 156, 18);
            title = tr("Scan paused");
            details = tr("The scan is paused. Resume or stop the scan when ready.");
        } else if (running && pending > 0) {
            color = red;
            title = tr("Threat detected");
            details = pending > 0
                ? tr("A threat was found while scanning continues. %1 detected infection(s) still need handling.").arg(pending)
                : tr("A threat was found while scanning continues. All detections have been handled.");
        } else if (running) {
            color = blue;
            title = tr("Scan in progress");
            details = tr("ClamAV is checking the selected targets.");
        } else if (infectionDetected_) {
            color = allHandled ? green : red;
            title = allHandled ? tr("Threats handled") : tr("Threats found");
            details = pending > 0
                ? tr("%1 detected infection(s) still need handling.").arg(pending)
                : tr("All detected infections have been handled.");
        }
        const int alpha = running && pulseOn_ ? 72 : 45;
        const QString background = allHandled
            ? QStringLiteral("qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(210, 55, 65, 55), stop:1 rgba(80, 170, 100, 65))")
            : QStringLiteral("rgba(%1, %2, %3, %4)").arg(color.red()).arg(color.green()).arg(color.blue()).arg(alpha);
        statusCard_->setStyleSheet(QStringLiteral(
            "QFrame#scanStatusCard { background: %1; border: 1px solid rgba(%2, %3, %4, 180); border-radius: 8px; }"
            "QFrame#scanStatusCard QLabel { border: none; background: transparent; }")
            .arg(background).arg(color.red()).arg(color.green()).arg(color.blue()));
        statusCardTitle_->setText(title);
        statusCardDetails_->setText(details);
        stopStatusButton_->setVisible(running && !waitingForTargets_);
        stopStatusButton_->setEnabled(running && !waitingForTargets_);
        const QString normalHeading = quarantine_ ? tr("Scanning and protecting with ClamAV")
                                                  : tr("Scanning with ClamAV");
        heading_->setText(normalHeading);
        heading_->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: 600; color: palette(window-text);"));
        if (running)
            setSearchIcon(pending > 0);
        else if (pending > 0 || (!running && infectionDetected_ && !allHandled))
            setStatusIcon(QColor(QStringLiteral("#da4453")), QChar('!'));
        else
            setStatusIcon(QColor(QStringLiteral("#50aa64")), QChar(0x2713));
    }

    static QColor activityColor(const QString &detection)
    {
        if (detection.isEmpty())
            return QColor(130, 130, 130);
        switch (detectionLevel(detection)) {
        case 1: return QColor(80, 170, 100);
        case 2: return QColor(155, 89, 182);
        default: return QColor(210, 55, 65);
        }
    }

    void updateActivityItem(int index)
    {
        if (!activityList_ || index < 0 || index >= activityEntries_.size())
            return;
        const ActivityEntry &entry = activityEntries_.at(index);
        QListWidgetItem *item = activityList_->item(index);
        const QColor color = activityColor(entry.detection);
        item->setText(entry.detection.isEmpty()
            ? tr("Scanned · %1").arg(QDir::toNativeSeparators(entry.path))
            : tr("Threat · %1\n%2").arg(QDir::toNativeSeparators(entry.path), entry.detection));
        item->setForeground(entry.detection.isEmpty() ? QColor(130, 130, 130) : color);
        item->setBackground(QColor(color.red(), color.green(), color.blue(), entry.detection.isEmpty() ? 12 : 28));
        item->setSizeHint(QSize(item->sizeHint().width(), entry.detection.isEmpty() ? 32 : 52));
    }

    void updateActivitySummary()
    {
        if (!activitySummary_)
            return;
        activitySummary_->setText(activityDetectionCount_ == 0
            ? tr("%1 file(s) scanned · no detections found.").arg(activityEntries_.size())
            : tr("%1 file(s) scanned · %2 detection(s) found.").arg(activityEntries_.size()).arg(activityDetectionCount_));
        activitySummary_->setStyleSheet(QStringLiteral("font-weight: 600; color: %1;")
            .arg(activityDetectionCount_ == 0 ? QStringLiteral("palette(mid)") : QStringLiteral("rgb(210, 55, 65)")));
    }

    QString targetDescription() const
    {
        QStringList names;
        for (const QString &path : paths_)
            names << QDir::toNativeSeparators(path);
        if (names.size() > 3)
            return tr("%1 targets · %2, %3, %4, and more")
                .arg(names.size()).arg(names.at(0)).arg(names.at(1)).arg(names.at(2));
        return tr("%1 target(s) · %2").arg(names.size()).arg(names.join(QStringLiteral(", ")));
    }

    QLabel *addCard(QHBoxLayout *layout, const QString &title, const QString &value,
                    QProgressBar **meter = nullptr)
    {
        auto *card = new QFrame(this);
        card->setFrameShape(QFrame::StyledPanel);
        card->setStyleSheet(QStringLiteral(
            "QFrame { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"));
        auto *cardLayout = new QVBoxLayout(card);
        auto *label = new QLabel(title, card);
        label->setStyleSheet(QStringLiteral("font-weight: 600;"));
        auto *valueLabel = new QLabel(value, card);
        valueLabel->setWordWrap(true);
        valueLabel->setMinimumHeight(34);
        cardLayout->addWidget(label);
        cardLayout->addWidget(valueLabel);
        if (meter) {
            *meter = new QProgressBar(card);
            (*meter)->setRange(0, 100);
            (*meter)->setValue(0);
            (*meter)->setTextVisible(false);
            (*meter)->setFixedHeight(7);
            (*meter)->setStyleSheet(QStringLiteral(
                "QProgressBar { border: none; border-radius: 3px; background: palette(midlight); }"
                "QProgressBar::chunk { border-radius: 3px; background: #3daee9; }"));
            cardLayout->addWidget(*meter);
        }
        layout->addWidget(card, 1);
        return valueLabel;
    }

    void setStatusIcon(const QColor &color, const QChar &mark)
    {
        QPixmap pixmap(36, 36);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        painter.drawEllipse(2, 2, 32, 32);
        if (!mark.isNull()) {
            painter.setPen(QPen(Qt::white, 3, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            if (mark == QChar(0x2713)) {
                painter.drawLine(QPointF(10, 18), QPointF(16, 24));
                painter.drawLine(QPointF(16, 24), QPointF(27, 12));
            } else if (mark == QChar('!')) {
                painter.drawLine(QPointF(18, 10), QPointF(18, 21));
                painter.drawPoint(QPointF(18, 27));
            } else {
                painter.drawLine(QPointF(11, 11), QPointF(25, 25));
                painter.drawLine(QPointF(25, 11), QPointF(11, 25));
            }
        }
        statusIcon_->setPixmap(pixmap);
    }

    void setSearchIcon(bool warning = false)
    {
        QIcon icon;
        for (const QString &name : {QStringLiteral("edit-find"), QStringLiteral("system-search"),
                                    QStringLiteral("search")}) {
            icon = QIcon::fromTheme(name);
            if (!icon.isNull())
                break;
        }
        QPixmap pixmap(36, 36);
        pixmap.fill(Qt::transparent);
        if (!icon.isNull()) {
            QPainter painter(&pixmap);
            painter.setRenderHint(QPainter::Antialiasing);
            painter.drawPixmap(0, 0, icon.pixmap(QSize(32, 32)));
        } else {
            setStatusIcon(QColor(QStringLiteral("#3daee9")), QChar('?'));
            pixmap = statusIcon_->pixmap(Qt::ReturnByValue);
        }
        if (warning) {
            QPainter painter(&pixmap);
            painter.setRenderHint(QPainter::Antialiasing);
            painter.setPen(QPen(Qt::white, 1));
            painter.setBrush(QColor(QStringLiteral("#da3748")));
            painter.drawEllipse(QRectF(22, 22, 14, 14));
            painter.setPen(QPen(Qt::white, 2, Qt::SolidLine, Qt::RoundCap));
            painter.drawLine(QPointF(29, 25), QPointF(29, 30));
            painter.drawPoint(QPointF(29, 33));
        }
        statusIcon_->setPixmap(pixmap);
    }

    qint64 processCpuTime() const
    {
        qint64 ticks = 0;
        bool found = false;
        for (const qint64 pid : pids_) {
            QFile stat(QStringLiteral("/proc/%1/stat").arg(pid));
            if (!stat.open(QIODevice::ReadOnly))
                continue;
            const QByteArray contents = stat.readAll();
            const int closingParenthesis = contents.lastIndexOf(')');
            if (closingParenthesis < 0)
                continue;
            const QList<QByteArray> fields = contents.mid(closingParenthesis + 1).simplified().split(' ');
            if (fields.size() < 13)
                continue;
            bool okUser = false, okKernel = false;
            const qint64 user = fields.at(11).toLongLong(&okUser);
            const qint64 kernel = fields.at(12).toLongLong(&okKernel);
            if (okUser && okKernel) {
                ticks += user + kernel;
                found = true;
            }
        }
        return found ? ticks : -1;
    }

    void readOutput()
    {
        const QByteArray text = process_->readAllStandardOutput() + process_->readAllStandardError();
        if (!text.isEmpty()) {
            bool detectionsChanged = false;
            const bool activityVisible = tabs_ && tabs_->currentWidget() == scanPage_;
            const QString incoming = QString::fromLocal8Bit(text);
            for (const QString &sourceLine : incoming.split(QLatin1Char('\n'))) {
                const QString line = sourceLine.trimmed();
                if (line.startsWith(QStringLiteral("SCAN_FILE: "))) {
                    currentFile_ = line.mid(QStringLiteral("SCAN_FILE: ").size());
                    activityEntries_.append({currentFile_, {}});
                    currentActivityIndex_ = activityEntries_.size() - 1;
                    if (activityVisible) {
                        activityList_->addItem(QString());
                        updateActivityItem(currentActivityIndex_);
                        updateActivitySummary();
                    }
                } else if (line.startsWith(QStringLiteral("SCAN_RESULT: "))) {
                    const QJsonDocument document = QJsonDocument::fromJson(
                        line.mid(QStringLiteral("SCAN_RESULT: ").size()).toUtf8());
                    const QJsonObject result = document.object();
                    const bool infected = result.value(QStringLiteral("infected")).toBool();
                    QString activityDetection;
                    if (infected) {
                        const QString activityMessage = result.value(QStringLiteral("message")).toString();
                        for (const QString &messageLine : activityMessage.split(QLatin1Char('\n'))) {
                            if (messageLine.trimmed().endsWith(QStringLiteral(" FOUND"), Qt::CaseInsensitive)) {
                                activityDetection = canonicalDetection(messageLine);
                                break;
                            }
                        }
                        if (activityDetection.isEmpty())
                            activityDetection = canonicalDetection(activityMessage.section(QLatin1Char('\n'), 0, 0));
                    }
                    if (activityVisible && currentActivityIndex_ >= 0) {
                        if (activityEntries_[currentActivityIndex_].detection.isEmpty()
                                && !activityDetection.isEmpty())
                            ++activityDetectionCount_;
                        activityEntries_[currentActivityIndex_].detection = activityDetection;
                        updateActivityItem(currentActivityIndex_);
                        updateActivitySummary();
                    } else if (currentActivityIndex_ >= 0
                               && activityEntries_[currentActivityIndex_].detection.isEmpty()
                               && !activityDetection.isEmpty()) {
                        ++activityDetectionCount_;
                    }
                    scanHashes_.insert(currentFile_, result.value(QStringLiteral("sha256")).toString());
                    if (infected) {
                        QString detection;
                        const QString message = result.value(QStringLiteral("message")).toString();
                        for (const QString &messageLine : message.split(QLatin1Char('\n'))) {
                            if (messageLine.trimmed().endsWith(QStringLiteral(" FOUND"), Qt::CaseInsensitive)) {
                                detection = canonicalDetection(messageLine);
                                break;
                            }
                        }
                        if (detection.isEmpty())
                            detection = canonicalDetection(message.section(QLatin1Char('\n'), 0, 0));
                        const QString detectionKey = currentFile_ + QLatin1Char('\n') + detection;
                        const bool knownThisScan = currentDetectionKeys_.contains(detectionKey);
                        const bool knownUnhandled = std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                            [this, &detection](const DetectionEntry &entry) {
                                return !entry.handled && !entry.deleted
                                    && entry.path == currentFile_
                                    && entry.detection.compare(detection, Qt::CaseInsensitive) == 0;
                            });
                        if (!knownThisScan) {
                            const int level = detectionLevel(detection);
                            writeAudit(QStringLiteral("scan-detection"), currentFile_,
                                       QStringLiteral("severity=%1 (%2); detection=%3")
                                           .arg(level).arg(detectionLevelLabel(level), detection));
                        }
                        if (!knownThisScan && !knownUnhandled)
                            detectedFiles_.append({currentFile_, detection, scanHashes_.value(currentFile_), {},
                                                   result.value(QStringLiteral("quarantined")).toBool(), false});
                        if (!knownThisScan && !knownUnhandled)
                            detectionsChanged = true;
                        currentDetectionKeys_.insert(detectionKey);
                        infectionDetected_ = true;
                    }
                }
                else if (line.startsWith(QStringLiteral("SHA-256: "))) {
                    const QString hash = line.mid(QStringLiteral("SHA-256: ").size()).trimmed();
                    scanHashes_.insert(currentFile_, hash);
                    for (auto &entry : detectedFiles_)
                        if (entry.path == currentFile_ && entry.sha256 != hash) {
                            entry.sha256 = hash;
                            detectionsChanged = true;
                        }
                }
            }
            if (detectionsChanged) {
                refreshDetectionsIfVisible();
                updateStatusCard();
            }
        }
    }

    bool resultsTabVisible() const
    {
        return tabs_ && tabs_->currentWidget() == detectionsPanel_;
    }

    void refreshDetectionsIfVisible()
    {
        if (resultsTabVisible())
            refreshDetectionsPanel();
    }

    void updateQueue()
    {
        const Stats stats = queryStats(socketPath_);
        if (!stats.valid) {
            queueStatus_->setText(tr("Waiting for clamd statistics…"));
            queueMeter_->setRange(0, 0);
            return;
        }
        queueMeter_->setRange(0, std::max(1, stats.maximum));
        queueMeter_->setValue(std::min(stats.live, std::max(1, stats.maximum)));
        queueStatus_->setText(tr("%1 queued · %2 active · %3 idle\n%4 MiB in use")
            .arg(stats.queue).arg(stats.live).arg(stats.idle).arg(stats.memory, 0, 'f', 1));
    }

    void refreshDetectionsPanel()
    {
        if (!detectionsList_)
            return;
        QString selectedPath = selectedDetectionPath_;
        QString selectedDetection = selectedDetectionName_;
        if (detectionsList_->currentItem()) {
            const int sourceIndex = detectionsList_->currentItem()->data(Qt::UserRole).toInt();
            if (sourceIndex >= 0 && sourceIndex < detectedFiles_.size()) {
                selectedPath = detectedFiles_.at(sourceIndex).path;
                selectedDetection = detectedFiles_.at(sourceIndex).detection;
            }
        }
        detectionsList_->clear();
        QList<int> order;
        for (int index = 0; index < detectedFiles_.size(); ++index)
            order.append(index);
        std::stable_sort(order.begin(), order.end(), [this](int left, int right) {
            const DetectionEntry &a = detectedFiles_.at(left);
            const DetectionEntry &b = detectedFiles_.at(right);
            if (a.handled != b.handled)
                return !a.handled;
            return detectionLevel(a.detection) > detectionLevel(b.detection);
        });
        for (const int sourceIndex : order) {
            const auto &detected = detectedFiles_.at(sourceIndex);
            const int level = detectionLevel(detected.detection);
            const QColor color = detectionLevelColor(level);
            auto *item = new QListWidgetItem(detectionsList_);
            auto *row = new QFrame(detectionsList_);
            row->setObjectName(QStringLiteral("detectionRow"));
            row->setStyleSheet(QStringLiteral(
                "QFrame#detectionRow { background: rgba(%1, %2, %3, 35); border: 1px solid rgba(%1, %2, %3, 120);"
                " border-left: 5px solid rgb(%1, %2, %3); border-radius: 5px; }")
                .arg(color.red()).arg(color.green()).arg(color.blue()));
            auto *rowLayout = new QHBoxLayout(row);
            rowLayout->setContentsMargins(10, 8, 10, 8);
            auto *handledState = new QLabel(row);
            handledState->setFixedWidth(26);
            handledState->setAlignment(Qt::AlignTop | Qt::AlignHCenter);
            const QStringList iconNames = detected.deleted
                ? QStringList{QStringLiteral("user-trash-full"), QStringLiteral("edit-delete")}
                : detected.handled
                ? QStringList{QStringLiteral("emblem-ok"), QStringLiteral("dialog-ok-apply")}
                : QStringList{QStringLiteral("dialog-warning"), QStringLiteral("dialog-error")};
            QIcon statusIcon;
            for (const QString &iconName : iconNames) {
                statusIcon = QIcon::fromTheme(iconName);
                if (!statusIcon.isNull())
                    break;
            }
            if (!statusIcon.isNull())
                handledState->setPixmap(statusIcon.pixmap(QSize(24, 24)));
            else
                handledState->setText(detected.deleted ? QStringLiteral("×")
                                                        : detected.handled ? QStringLiteral("✓") : QStringLiteral("!"));
            handledState->setStyleSheet(QStringLiteral("font-size: 22px; font-weight: 700; color: %1;")
                                        .arg(detected.deleted || detected.handled
                                                 ? QStringLiteral("rgb(80, 170, 100)")
                                                 : QStringLiteral("rgb(210, 55, 65)")));
            rowLayout->addWidget(handledState);
            auto *textColumn = new QWidget(row);
            auto *textLayout = new QVBoxLayout(textColumn);
            textLayout->setContentsMargins(0, 0, 0, 0);
            auto *file = new QLabel(QDir::toNativeSeparators(detected.path), row);
            file->setToolTip(detected.path);
            file->setStyleSheet(QStringLiteral("font-weight: 600;"));
            textLayout->addWidget(file);
            auto *levelLabel = new QLabel(detectionLevelLabel(level), row);
            levelLabel->setStyleSheet(QStringLiteral("font-weight: 600; color: rgb(%1, %2, %3);")
                                       .arg(color.red()).arg(color.green()).arg(color.blue()));
            textLayout->addWidget(levelLabel);
            auto *detection = new QLabel(detected.detection, row);
            detection->setWordWrap(true);
            textLayout->addWidget(detection);
            if (detected.deleted) {
                auto *deleted = new QLabel(tr("✓ Deleted"), row);
                deleted->setStyleSheet(QStringLiteral("font-weight: 600; color: rgb(80, 170, 100);"));
                textLayout->addWidget(deleted);
            }
            rowLayout->addWidget(textColumn, 1);
            item->setData(Qt::UserRole, sourceIndex);
            item->setSizeHint(row->sizeHint());
            detectionsList_->setItemWidget(item, row);
        }
        for (int row = 0; row < detectionsList_->count(); ++row) {
            const int sourceIndex = detectionsList_->item(row)->data(Qt::UserRole).toInt();
            if (detectedFiles_.at(sourceIndex).path == selectedPath
                    && detectedFiles_.at(sourceIndex).detection == selectedDetection) {
                detectionsList_->setCurrentRow(row);
                break;
            }
        }
        if (detectionsList_->currentRow() < 0 && detectionsList_->count() > 0)
            detectionsList_->setCurrentRow(0);
        updateSelectedDetection();
        const int count = detectedFiles_.size();
        if (tabs_ && detectionsPanel_)
            tabs_->setTabText(tabs_->indexOf(detectionsPanel_), tr("Results (%1)").arg(count));
    }

    DetectionEntry *selectedDetectionEntry()
    {
        if (!detectionsList_ || !detectionsList_->currentItem()
                || !detectionsList_->currentItem()->isSelected())
            return nullptr;
        const int sourceIndex = detectionsList_->currentItem()->data(Qt::UserRole).toInt();
        return sourceIndex >= 0 && sourceIndex < detectedFiles_.size()
            ? &detectedFiles_[sourceIndex] : nullptr;
    }

    void updateSelectedDetection()
    {
        DetectionEntry *entry = selectedDetectionEntry();
        const bool hasEntry = entry != nullptr;
        if (hasEntry) {
            selectedDetectionPath_ = entry->path;
            selectedDetectionName_ = entry->detection;
        } else {
            selectedDetectionPath_.clear();
            selectedDetectionName_.clear();
        }
        lookupButton_->setEnabled(hasEntry);
        virusTotalButton_->setEnabled(hasEntry);
        detailQuarantineButton_->setEnabled(hasEntry && !entry->handled && !entry->deleted);
        detailDeleteButton_->setEnabled(hasEntry && !entry->deleted);
        detailQuarantineAllButton_->setEnabled(std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
            [](const DetectionEntry &candidate) { return !candidate.handled && !candidate.deleted; }));
        detailDeleteAllButton_->setEnabled(std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
            [](const DetectionEntry &candidate) { return !candidate.deleted; }));
        if (!hasEntry) {
            detailEmptyState_->setVisible(true);
            detailContent_->setVisible(false);
            detailDetection_->clear();
            detailSeverity_->clear();
            detailPath_->clear();
            detailHash_->clear();
            detailStatus_->clear();
            detailStatusIcon_->setStatusIcon(QIcon());
            detailStatusIcon_->clear();
            detailMeter_->setValue(0);
            return;
        }
        detailEmptyState_->setVisible(false);
        detailContent_->setVisible(true);
        const int level = detectionLevel(entry->detection);
        const QColor color = detectionLevelColor(level);
        detailDetection_->setText(entry->detection);
        detailSeverity_->setText(detectionLevelLabel(level));
        detailSeverity_->setStyleSheet(QStringLiteral("font-weight: 600; color: rgb(%1, %2, %3);")
                                       .arg(color.red()).arg(color.green()).arg(color.blue()));
        detailMeter_->setValue(level);
        detailMeter_->setStyleSheet(QStringLiteral(
            "QProgressBar { border: 0; border-radius: 4px; background: palette(midlight); }"
            "QProgressBar::chunk { border-radius: 4px; background: rgb(%1, %2, %3); }")
            .arg(color.red()).arg(color.green()).arg(color.blue()));
        detailPath_->setText(QDir::toNativeSeparators(entry->path));
        detailHash_->setText(entry->sha256.isEmpty() ? tr("Unavailable") : entry->sha256);
        detailStatus_->setText(entry->deleted ? tr("Status: Deleted")
            : entry->handled ? tr("Status: Quarantined") : tr("Status: Needs attention"));
        const QStringList statusIconNames = entry->deleted
            ? QStringList{QStringLiteral("user-trash-full"), QStringLiteral("edit-delete")}
            : entry->handled
            ? QStringList{QStringLiteral("emblem-ok"), QStringLiteral("dialog-ok-apply")}
            : QStringList{QStringLiteral("dialog-warning"), QStringLiteral("dialog-error")};
        QIcon statusIcon;
        for (const QString &iconName : statusIconNames) {
            statusIcon = QIcon::fromTheme(iconName);
            if (!statusIcon.isNull())
                break;
        }
        detailStatusIcon_->setStyleSheet(QStringLiteral("color: %1;")
            .arg(entry->deleted || entry->handled ? QStringLiteral("rgb(80, 170, 100)")
                                                   : QStringLiteral("rgb(210, 55, 65)")));
        if (!statusIcon.isNull()) {
            detailStatusIcon_->setStatusIcon(statusIcon);
        } else {
            detailStatusIcon_->setStatusIcon(QIcon());
            detailStatusIcon_->setText(entry->deleted ? QStringLiteral("×")
                : entry->handled ? QStringLiteral("✓") : QStringLiteral("!"));
        }
    }

    void lookupSelectedDetection(bool virusTotal)
    {
        DetectionEntry *entry = selectedDetectionEntry();
        if (!entry)
            return;
        const QString query = lookupDetectionName(entry->detection).left(256);
        if (!virusTotal) {
            QDesktopServices::openUrl(QUrl(QStringLiteral("https://duckduckgo.com/?q=ClamAV+")
                                           + QString::fromLatin1(QUrl::toPercentEncoding(query))));
            return;
        }
        const bool validHash = entry->sha256.size() == 64
            && QRegularExpression(QStringLiteral("^[0-9a-fA-F]{64}$")).match(entry->sha256).hasMatch();
        const QString target = validHash
            ? QStringLiteral("https://www.virustotal.com/gui/file/") + entry->sha256 + QStringLiteral("/detection")
            : QStringLiteral("https://www.virustotal.com/gui/search/")
                + QString::fromLatin1(QUrl::toPercentEncoding(query));
        QDesktopServices::openUrl(QUrl(target));
    }

    void updateMetrics()
    {
        if (process_ && process_->state() != QProcess::NotRunning) {
            pids_ = {process_->processId()};
            const QList<qint64> daemons = clamdPids();
            for (const qint64 pid : daemons) {
                if (!pids_.contains(pid))
                    pids_ << pid;
            }
            cpuTarget_ = daemons.isEmpty() ? tr("Scanner") : tr("ClamAV");
        }
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - started_).count();
        const double delta = elapsed - sampleTime_;
        const qint64 cpu = processCpuTime();
        if (cpu >= 0 && cpuSample_ >= 0 && delta > 0) {
            const double ticksPerSecond = std::max(1L, sysconf(_SC_CLK_TCK));
            const double cpuSeconds = std::max(0.0, (cpu - cpuSample_) / ticksPerSecond);
            const double usage = std::max(0.0, cpuSeconds / delta * 100.0);
            cpuPeak_ = std::max(cpuPeak_, usage);
            cpuSeconds_ += cpuSeconds;
            cpuMeter_->setValue(std::min(100, std::max(0, static_cast<int>(usage))));
            cpuStatus_->setText(tr("%1% CPU\n%2 active").arg(usage, 0, 'f', 1).arg(cpuTarget_));
        }
        cpuSample_ = cpu;
        sampleTime_ = elapsed;
    }

    void cancelOrClose()
    {
        if (!waitingForTargets_ && !finished_) {
            QMessageBox warning(this);
            warning.setIcon(QMessageBox::Warning);
            warning.setWindowTitle(tr("Stop incomplete scan?"));
            warning.setText(tr("The scan has not finished yet. Stopping it may leave some locations unchecked."));
            warning.setInformativeText(tr("Are you sure you want to stop the scan?"));
            QAbstractButton *stopButton = warning.addButton(tr("Stop scan"), QMessageBox::AcceptRole);
            warning.addButton(tr("Continue scanning"), QMessageBox::RejectRole);
            warning.setDefaultButton(QMessageBox::Cancel);
            warning.exec();
            if (warning.clickedButton() != stopButton)
                return;
            cancelled_ = true;
            writeAudit(QStringLiteral("scan-stop"), QString(),
                       QStringLiteral("paused=%1").arg(paused_ ? 1 : 0));
            if (paused_) {
                ::kill(static_cast<pid_t>(process_->processId()), SIGCONT);
                paused_ = false;
            }
            pauseButton_->setEnabled(false);
            action_->setEnabled(false);
            stopStatusButton_->setEnabled(false);
            process_->terminate();
            QTimer::singleShot(1500, this, [this] {
                if (process_->state() != QProcess::NotRunning)
                    process_->kill();
            });
            return;
        }
        if (!confirmCloseWithUnhandledInfections())
            return;
        if (waitingForTargets_) {
            accept();
            return;
        }
        if (finished_) {
            logScanClose();
            accept();
            return;
        }
    }

    void pauseOrResumeScan()
    {
        if (!process_ || process_->state() == QProcess::NotRunning || finished_)
            return;
        const pid_t pid = static_cast<pid_t>(process_->processId());
        if (pid <= 0)
            return;
        if (paused_) {
            if (::kill(pid, SIGCONT) != 0)
                return;
            paused_ = false;
            writeAudit(QStringLiteral("scan-continue"), QString(), QStringLiteral("scan resumed"));
            pauseButton_->setText(tr("Pause scan"));
            pauseButton_->setIcon(QIcon::fromTheme(QStringLiteral("media-playback-pause")));
            progress_->setFormat(tr("Scanning…"));
            summary_->setText(tr("Scan resumed."));
            pulseTimer_.start();
        } else {
            if (::kill(pid, SIGSTOP) != 0)
                return;
            paused_ = true;
            writeAudit(QStringLiteral("scan-pause"), QString(), QStringLiteral("scan paused"));
            pauseButton_->setText(tr("Continue scan"));
            pauseButton_->setIcon(QIcon::fromTheme(QStringLiteral("media-playback-start")));
            progress_->setFormat(tr("Paused"));
            summary_->setText(tr("Scan paused."));
            pulseTimer_.stop();
        }
        updateStatusCard();
    }

    void scanFinished(int exitCode)
    {
        readOutput();
        metricsTimer_.stop();
        statsTimer_.stop();
        fileDisplayTimer_.stop();
        updateMetrics();
        finished_ = true;
        paused_ = false;
        waitingForTargets_ = false;
        pulseTimer_.stop();
        resultCode_ = cancelled_ ? 130 : (exitCode == 0 ? 0 : exitCode == 1 ? 1 : (exitCode == 0 ? 1 : exitCode));
        progress_->setRange(0, 100);
        progress_->setValue(100);
        progress_->setFormat(tr("Complete"));
        const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
        const QString summary = cancelled_ ? tr("The scan was cancelled.")
            : exitCode == 0 ? tr("No threats found.")
            : exitCode == 1 ? tr("Threats were identified.")
                            : tr("The scan could not be completed.");
        writeAudit(QStringLiteral("scan-finished"), QString(),
                   QStringLiteral("exit=%1; cancelled=%2; detections=%3")
                       .arg(exitCode).arg(cancelled_ ? 1 : 0).arg(detectedFiles_.size()),
                   !cancelled_ && exitCode <= 1);
        statusText_ = tr("Scanner: %1 · Elapsed: %2 s").arg(scanner_).arg(elapsed, 0, 'f', 1);
        if (cancelled_ || exitCode > 1) {
            setStatusIcon(QColor(QStringLiteral("#f39c12")), QChar('!'));
        } else if (exitCode == 1) {
            setStatusIcon(QColor(QStringLiteral("#da4453")), QChar(0x00D7));
        } else {
            setStatusIcon(QColor(QStringLiteral("#27ae60")), QChar(0x2713));
        }
        summary_->setText(summary);
        targetSummary_->setText(statusText_);
        currentFileLabel_->setText(tr("Current file: scan complete"));
        updateStatusCard();
        action_->setEnabled(true);
        action_->setText(tr("Close"));
        pauseButton_->setEnabled(false);
        stopStatusButton_->setVisible(false);
        stopStatusButton_->setEnabled(false);
        rescanButton_->setText(tr("Rescan"));
        setTargetEditingEnabled(true);
        if (infectionDetected_ && !detectedFiles_.isEmpty() && tabs_)
            tabs_->setCurrentWidget(detectionsPanel_);
        const bool canQuarantine = exitCode == 1 && infectionDetected_
            && std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                           [](const DetectionEntry &entry) { return !entry.handled; });
        quarantineButton_->setEnabled(canQuarantine);
        if (canQuarantine && (quarantine_ || quarantineCheckBox_->isChecked()))
            quarantineDetectedFiles();
        cpuStatus_->setText(tr("%1: average %2% · peak %3%").arg(cpuTarget_)
            .arg(elapsed > 0 ? cpuSeconds_ / elapsed * 100.0 : 0.0, 0, 'f', 1)
            .arg(cpuPeak_, 0, 'f', 1));
        cpuMeter_->setValue(std::min(100, std::max(0, static_cast<int>(cpuPeak_))));
        activityList_->scrollToBottom();
    }

    void closeEvent(QCloseEvent *event) override
    {
        if (!confirmCloseWithUnhandledInfections()) {
            event->ignore();
            return;
        }
        if (finished_)
            logScanClose();
        if (!finished_ && process_->state() != QProcess::NotRunning)
            process_->kill();
        event->accept();
    }

    bool confirmCloseWithUnhandledInfections()
    {
        const int pending = std::count_if(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                          [](const DetectionEntry &entry) {
                                              return !entry.handled && !entry.deleted;
                                          });
        if (pending == 0)
            return true;

        QMessageBox warning(this);
        warning.setIcon(QMessageBox::Critical);
        warning.setWindowTitle(tr("Unhandled infections"));
        warning.setText(QStringLiteral("<span style=\"color:#da4453; font-weight:600;\">%1</span>")
                        .arg(tr("%1 infection(s) are still unhandled.").arg(pending)));
        warning.setInformativeText(tr("Closing this window will leave the infected files in place. Are you sure you want to continue?"));
        auto *quarantineAndClose = warning.addButton(tr("Quarantine all and close"), QMessageBox::AcceptRole);
        auto *closeAnyway = warning.addButton(tr("Close anyway"), QMessageBox::DestructiveRole);
        auto *cancel = warning.addButton(tr("Cancel"), QMessageBox::RejectRole);
        closeAnyway->setStyleSheet(QStringLiteral("color: #da4453; font-weight: 600;"));
        warning.setDefaultButton(cancel);
        warning.exec();
        if (warning.clickedButton() == quarantineAndClose) {
            quarantineDetectedFiles();
            return std::none_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                [](const DetectionEntry &entry) {
                                    return !entry.handled && !entry.deleted;
                                });
        }
        return warning.clickedButton() == closeAnyway;
    }

    void logScanClose()
    {
        if (closeLogged_ || detectedFiles_.isEmpty())
            return;
        const bool allHandled = std::all_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                            [](const DetectionEntry &entry) {
                                                return entry.handled || entry.deleted;
                                            });
        writeAudit(QStringLiteral("scan-close"), QString(),
                   allHandled
                       ? QStringLiteral("all detections handled; count=%1").arg(detectedFiles_.size())
                       : QStringLiteral("unhandled detections remain; count=%1").arg(
                             std::count_if(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                           [](const DetectionEntry &entry) {
                                               return !entry.handled && !entry.deleted;
                                           })),
                   allHandled);
        closeLogged_ = true;
    }

    void quarantineDetectedFiles()
    {
        if (detectedFiles_.isEmpty()) {
            QMessageBox::warning(this, tr("ClamAV"),
                                 tr("The detected file paths could not be determined."));
            return;
        }
        quarantineButton_->setEnabled(false);
        quarantineCheckBox_->setEnabled(false);
        int quarantined = 0;
        int pending = 0;
        for (auto &detected : detectedFiles_) {
            if (detected.handled)
                continue;
            ++pending;
            if (quarantineEntry(detected))
                ++quarantined;
        }
        refreshDetectionsIfVisible();
        updateStatusCard();
        if (quarantined == pending) {
            quarantineButton_->setEnabled(false);
            statusCardDetails_->setText(tr("Detected files were moved to quarantine."));
        } else {
            quarantineButton_->setEnabled(true);
            quarantineCheckBox_->setEnabled(true);
            QMessageBox::warning(this, tr("ClamAV"),
                                     tr("%1 of %2 detected files could be quarantined.")
                                         .arg(quarantined).arg(pending));
        }
    }

    bool quarantineEntry(DetectionEntry &detected)
    {
        const QByteArray source = detected.path.toLocal8Bit();
        const QByteArray name = QFileInfo(detected.path).fileName().toLocal8Bit();
        const QByteArray detection = detected.detection.toLocal8Bit();
        QString hash = detected.sha256;
        if (hash.isEmpty()) {
            char calculated[65];
            if (!clamav_quarantine_hash_file(source.constData(), calculated))
                return false;
            hash = QString::fromLatin1(calculated);
            detected.sha256 = hash;
        }
        const QByteArray sha256 = hash.toLatin1();
        const QByteArray component = "plasma";
        const clamav_quarantine_metadata metadata{
            component.constData(), name.constData(), source.constData(),
            detection.constData(), sha256.constData()};
        char id[CLAMAV_QUARANTINE_ID_LENGTH];
        char payload[PATH_MAX];
        const QString detail = QStringLiteral("severity=%1 (%2); detection=%3")
            .arg(detectionLevel(detected.detection))
            .arg(detectionLevelLabel(detectionLevel(detected.detection)))
            .arg(detected.detection);
        if (!clamav_quarantine_store(source.constData(), &metadata, 1, id, payload)) {
            writeAudit(QStringLiteral("scan-quarantine"), detected.path, detail, false);
            return false;
        }
        detected.handled = true;
        detected.quarantineId = QString::fromLatin1(id);
        writeAudit(QStringLiteral("scan-quarantine"), detected.path, detail);
        return true;
    }

    void quarantineSelectedDetection()
    {
        DetectionEntry *entry = selectedDetectionEntry();
        if (!entry || entry->handled || entry->deleted)
            return;
        if (!quarantineEntry(*entry)) {
            QMessageBox::warning(this, tr("ClamAV"), tr("The detected file could not be quarantined."));
            return;
        }
        refreshDetectionsIfVisible();
        updateStatusCard();
        quarantineButton_->setEnabled(!quarantine_ && std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                                   [](const DetectionEntry &candidate) {
                                                       return !candidate.handled && !candidate.deleted;
                                                   }));
    }

    void deleteSelectedDetection()
    {
        DetectionEntry *entry = selectedDetectionEntry();
        if (entry)
            deleteDetection(entry->path, entry->detection);
    }

    bool deleteEntry(DetectionEntry &entry)
    {
        bool success = false;
        if (entry.handled) {
            if (entry.quarantineId.isEmpty()) {
                struct clamav_quarantine_entry *entries = nullptr;
                size_t count = 0;
                if (clamav_quarantine_list(&entries, &count)) {
                    for (size_t i = 0; i < count; ++i) {
                        if (QString::fromLocal8Bit(entries[i].source) == entry.path) {
                            entry.quarantineId = QString::fromLatin1(entries[i].id);
                            break;
                        }
                    }
                    clamav_quarantine_list_free(entries);
                }
            }
            success = !entry.quarantineId.isEmpty()
                && clamav_quarantine_delete(entry.quarantineId.toLatin1().constData());
        } else {
            success = QFile::remove(entry.path);
            writeAudit(QStringLiteral("scan-delete"), entry.path,
                       QStringLiteral("severity=%1 (%2); detection=%3")
                           .arg(detectionLevel(entry.detection))
                           .arg(detectionLevelLabel(detectionLevel(entry.detection)))
                           .arg(entry.detection), success);
        }
        if (success)
            entry.deleted = true;
        return success;
    }

    void deleteAllDetections()
    {
        QList<DetectionEntry *> entries;
        for (auto &entry : detectedFiles_)
            if (!entry.deleted)
                entries.append(&entry);
        if (entries.isEmpty())
            return;
        if (QMessageBox::question(this, tr("Delete all detections"),
                tr("Permanently delete all %1 detected files? This cannot be undone.").arg(entries.size()),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
            return;
        int failures = 0;
        for (DetectionEntry *entry : entries)
            if (!deleteEntry(*entry))
                ++failures;
        refreshDetectionsIfVisible();
        updateStatusCard();
        if (failures > 0)
            QMessageBox::warning(this, tr("Delete incomplete"),
                                 tr("%1 detection(s) could not be deleted.").arg(failures));
    }

    void deleteDetection(const QString &path, const QString &detection)
    {
        auto entry = std::find_if(detectedFiles_.begin(), detectedFiles_.end(),
                                  [&path, &detection](const DetectionEntry &candidate) {
                                      return candidate.path == path && candidate.detection == detection;
                                  });
        if (entry == detectedFiles_.end() || entry->deleted)
            return;
        const QString question = entry->handled
            ? tr("Permanently delete this quarantined infection? This cannot be undone.")
            : tr("Permanently delete the infected file? This cannot be undone.");
        if (QMessageBox::question(this, tr("Delete infection"), question,
                                  QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
                != QMessageBox::Yes)
            return;

        const bool success = deleteEntry(*entry);
        if (!success) {
            QMessageBox::warning(this, tr("Delete infection"),
                                 tr("The infection could not be deleted."));
            return;
        }
        quarantineButton_->setEnabled(!quarantine_ && std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                                   [](const DetectionEntry &candidate) {
                                                       return !candidate.handled && !candidate.deleted;
                                                   }));
        refreshDetectionsIfVisible();
        updateStatusCard();
    }

    QString scanner_;
    QStringList paths_;
    bool quarantine_ = false;
    QString scanId_;
    bool waitingForTargets_ = false;
    QString socketPath_;
    QString cpuTarget_ = tr("Scanner");
    QString statusText_;
    QList<DetectionEntry> detectedFiles_;
    QList<ActivityEntry> activityEntries_;
    int activityDetectionCount_ = 0;
    QString selectedDetectionPath_;
    QString selectedDetectionName_;
    QSet<QString> currentDetectionKeys_;
    int currentActivityIndex_ = -1;
    QHash<QString, QString> scanHashes_;
    QString currentFile_;
    QList<qint64> pids_;
    QProcess *process_ = nullptr;
    QLabel *queueStatus_ = nullptr;
    QLabel *cpuStatus_ = nullptr;
    QProgressBar *queueMeter_ = nullptr;
    QProgressBar *cpuMeter_ = nullptr;
    QLabel *statusIcon_ = nullptr;
    QLabel *heading_ = nullptr;
    QLabel *summary_ = nullptr;
    QLabel *targetSummary_ = nullptr;
    QLabel *currentFileLabel_ = nullptr;
    QLabel *activitySummary_ = nullptr;
    QFrame *statusCard_ = nullptr;
    QLabel *statusCardTitle_ = nullptr;
    QLabel *statusCardDetails_ = nullptr;
    QPushButton *stopStatusButton_ = nullptr;
    QPushButton *openQuarantineButton_ = nullptr;
    QPushButton *quarantineButton_ = nullptr;
    QCheckBox *quarantineCheckBox_ = nullptr;
    QTabWidget *tabs_ = nullptr;
    QWidget *scanPage_ = nullptr;
    QFrame *targetsPanel_ = nullptr;
    QListWidget *pathsList_ = nullptr;
    QPushButton *addFilesButton_ = nullptr;
    QPushButton *addFolderButton_ = nullptr;
    QPushButton *removePathsButton_ = nullptr;
    QPushButton *clearPathsButton_ = nullptr;
    QPushButton *rescanButton_ = nullptr;
    QFrame *detectionsPanel_ = nullptr;
    QListWidget *detectionsList_ = nullptr;
    QFrame *detailsPanel_ = nullptr;
    QLabel *detailEmptyState_ = nullptr;
    QWidget *detailContent_ = nullptr;
    QLabel *detailTitle_ = nullptr;
    QLabel *detailDetection_ = nullptr;
    QLabel *detailSeverity_ = nullptr;
    QProgressBar *detailMeter_ = nullptr;
    QLabel *detailPath_ = nullptr;
    QLabel *detailHash_ = nullptr;
    QLabel *detailStatus_ = nullptr;
    ScaledIconLabel *detailStatusIcon_ = nullptr;
    QPushButton *lookupButton_ = nullptr;
    QPushButton *virusTotalButton_ = nullptr;
    QPushButton *detailsToggleButton_ = nullptr;
    QPushButton *detailQuarantineButton_ = nullptr;
    QPushButton *detailDeleteButton_ = nullptr;
    QPushButton *detailQuarantineAllButton_ = nullptr;
    QPushButton *detailDeleteAllButton_ = nullptr;
    QProgressBar *progress_ = nullptr;
    QListWidget *activityList_ = nullptr;
    QListWidget *logView_ = nullptr;
    QLineEdit *logFilter_ = nullptr;
    QPushButton *logRefreshButton_ = nullptr;
    bool logNewestFirst_ = true;
    QFileSystemWatcher *logWatcher_ = nullptr;
    QTimer logRefreshTimer_;
    QString logPath_;
    QPushButton *action_ = nullptr;
    QPushButton *pauseButton_ = nullptr;
    QTimer metricsTimer_, statsTimer_, fileDisplayTimer_;
    QTimer pulseTimer_;
    std::chrono::steady_clock::time_point started_;
    qint64 cpuSample_ = -1;
    double sampleTime_ = 0.0, cpuSeconds_ = 0.0, cpuPeak_ = 0.0;
    bool cancelled_ = false, finished_ = false, paused_ = false, infectionDetected_ = false, pulseOn_ = false;
    bool closeLogged_ = false;
    int resultCode_ = 130;

public:
    int resultCode() const { return resultCode_; }
};
}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QTranslator dutch;
    if (QLocale().language() == QLocale::Dutch
            && dutch.load(QStringLiteral("clamav-scan_nl"), QStringLiteral(CLAMAV_TRANSLATION_DIR)))
        app.installTranslator(&dutch);
    QCommandLineParser parser;
    parser.addHelpOption();
    QCommandLineOption scannerOption(QStringLiteral("scanner"), QStringLiteral("Scanner executable"), QStringLiteral("scanner"));
    QCommandLineOption quarantineOption(QStringLiteral("quarantine"), QStringLiteral("Scan and quarantine infected files"));
    parser.addOption(scannerOption);
    parser.addOption(quarantineOption);
    parser.addPositionalArgument(QStringLiteral("path"), QStringLiteral("Files or directories to scan"));
    parser.process(app);
    const QStringList paths = parser.positionalArguments();
    if (!parser.isSet(scannerOption) && !parser.isSet(quarantineOption))
        return 2;
    QString scanner = QStandardPaths::findExecutable(QStringLiteral("clamav-scan-quarantine-helper"));
    if (scanner.isEmpty())
        return 2;
    ScanDialog dialog(scanner, paths, parser.isSet(quarantineOption));
    dialog.exec();
    return dialog.resultCode();
}
