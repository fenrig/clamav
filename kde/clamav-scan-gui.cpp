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
#include <QLocalSocket>
#include <QMessageBox>
#include <QProcess>
#include <QProgressBar>
#include <QPainter>
#include <QPushButton>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTextEdit>
#include <QTextCursor>
#include <QTimer>
#include <QLocale>
#include <QTranslator>
#include <QVBoxLayout>
#include <QDialog>
#include <QDesktopServices>
#include <QScrollArea>
#include <QListWidget>
#include <QSplitter>
#include <QTabWidget>
#include <QUrl>

#include "../quarantine/quarantine.h"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <dirent.h>
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

QString formatBytes(double value)
{
    const QStringList units = {QStringLiteral("B"), QStringLiteral("KiB"),
        QStringLiteral("MiB"), QStringLiteral("GiB")};
    int unit = 0;
    while (value >= 1024.0 && unit < units.size() - 1) {
        value /= 1024.0;
        ++unit;
    }
    return QStringLiteral("%1 %2").arg(value, 0, 'f', 1).arg(units.at(unit));
}

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
        : scanner_(scanner), paths_(paths), quarantine_(quarantine), started_(std::chrono::steady_clock::now())
    {
        setWindowTitle(tr("ClamAV virus scan"));
        setWindowIcon(QIcon::fromTheme(QStringLiteral("clamav")));
        resize(900, 620);
        setMinimumSize(720, 500);

        auto *layout = new QVBoxLayout(this);
        auto *headingRow = new QHBoxLayout;
        statusIcon_ = new QLabel(this);
        statusIcon_->setFixedSize(36, 36);
        setStatusIcon(QColor(QStringLiteral("#3daee9")), QChar());
        headingRow->addWidget(statusIcon_);
        auto *heading = new QLabel(quarantine_ ? tr("Scanning and protecting with ClamAV")
                                                : tr("Scanning with ClamAV"), this);
        heading->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: 600;"));
        headingRow->addWidget(heading);
        headingRow->addStretch();
        layout->addLayout(headingRow);

        tabs_ = new QTabWidget(this);
        tabs_->setTabPosition(QTabWidget::West);
        auto *scanPage = new QWidget(tabs_);
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
        openQuarantineButton_ = new QPushButton(tr("Open quarantine"), statusCard_);
        openQuarantineButton_->setIcon(QIcon::fromTheme(QStringLiteral("clamav-quarantine"),
                                                         QIcon::fromTheme(QStringLiteral("folder-open"))));
        statusLayout->addWidget(openQuarantineButton_);
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
        layout->addWidget(targetSummary_);

        tabs_->addTab(scanPage, tr("Scan"));
        layout->addWidget(tabs_, 1);

        auto *cards = new QHBoxLayout;
        queueStatus_ = addCard(cards, tr("Queue"), tr("Measuring…"));
        cpuStatus_ = addCard(cards, tr("CPU"), tr("Measuring…"));
        ioStatus_ = addCard(cards, tr("Disk I/O"), tr("Measuring…"));
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
        output_ = new QTextEdit(activity);
        output_->setReadOnly(true);
        output_->setLineWrapMode(QTextEdit::NoWrap);
        output_->setPlaceholderText(tr("Threats will appear here if ClamAV detects any."));
        output_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        activityLayout->addWidget(output_);
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
        action_ = new QPushButton(tr("Cancel"), this);
        connect(action_, &QPushButton::clicked, this, [this] { cancelOrClose(); });
        buttons->addWidget(action_);
        scanLayout->addLayout(buttons);

        process_ = new QProcess(this);
        connect(process_, &QProcess::readyReadStandardOutput, this, [this] { readOutput(); });
        connect(process_, &QProcess::readyReadStandardError, this, [this] { readOutput(); });
        connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int code, QProcess::ExitStatus) { scanFinished(code); });
        QStringList arguments{QStringLiteral("--scan-only")};
        arguments += paths_;
        process_->start(scanner_, arguments);
        pids_ = {process_->processId()};

        connect(&metricsTimer_, &QTimer::timeout, this, [this] { updateMetrics(); });
        metricsTimer_.start(500);
        connect(&statsTimer_, &QTimer::timeout, this, [this] { updateQueue(); });
        statsTimer_.start(1000);
        updateQueue();
        fileDisplayTimer_.setInterval(150);
        connect(&fileDisplayTimer_, &QTimer::timeout, this, [this] {
            if (!currentFile_.isEmpty())
                currentFileLabel_->setText(tr("Current file: %1").arg(QDir::toNativeSeparators(currentFile_)));
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
        detailDetection_ = new QLabel(detailContent_);
        detailDetection_->setWordWrap(true);
        detailSeverity_ = new QLabel(detailsPanel_);
        detailSeverity_->setStyleSheet(QStringLiteral("font-weight: 600;"));
        detailForm->addRow(tr("Detection:"), detailDetection_);
        detailPath_ = new QLabel(detailContent_);
        detailPath_->setWordWrap(true);
        detailForm->addRow(tr("Source path:"), detailPath_);
        detailHash_ = new QLabel(detailContent_);
        detailHash_->setWordWrap(true);
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
        detailStatusIcon_ = new QLabel(detailContent_);
        detailStatusIcon_->setFixedSize(48, 48);
        detailStatusIcon_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        detailContentLayout->addWidget(detailStatusIcon_);
        detailContentLayout->addStretch();
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
        lookupButton_ = new QPushButton(tr("Look up on DuckDuckGo"), detailsPanel_);
        virusTotalButton_ = new QPushButton(tr("Look up on VirusTotal"), detailsPanel_);
        detailQuarantineButton_ = new QPushButton(tr("Quarantine"), detailsPanel_);
        detailDeleteButton_ = new QPushButton(tr("Delete permanently"), detailsPanel_);
        detailQuarantineAllButton_ = new QPushButton(tr("Quarantine all"), actionBar);
        detailDeleteAllButton_ = new QPushButton(tr("Delete all"), actionBar);
        lookupButton_->setIcon(QIcon::fromTheme(QStringLiteral("system-search"),
                                                QIcon::fromTheme(QStringLiteral("search"))));
        virusTotalButton_->setIcon(QIcon::fromTheme(QStringLiteral("applications-internet"),
                                                     QIcon::fromTheme(QStringLiteral("internet-services"))));
        detailQuarantineButton_->setIcon(QIcon::fromTheme(QStringLiteral("security-high"),
                                                           QIcon::fromTheme(QStringLiteral("folder-locked"))));
        detailDeleteButton_->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete"),
                                                       QIcon::fromTheme(QStringLiteral("delete"))));
        detailQuarantineAllButton_->setIcon(QIcon::fromTheme(QStringLiteral("security-high"),
                                                              QIcon::fromTheme(QStringLiteral("folder-locked"))));
        detailDeleteAllButton_->setIcon(QIcon::fromTheme(QStringLiteral("trash-empty"),
                                                          QIcon::fromTheme(QStringLiteral("edit-delete"))));
        auto *selectedActions = new QHBoxLayout;
        selectedActions->addWidget(lookupButton_);
        selectedActions->addWidget(virusTotalButton_);
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
        panelLayout->addWidget(splitter, 1);
        panelLayout->addWidget(actionBar);
        detailsPanel_->setStyleSheet(QStringLiteral(
            "QFrame#scanSummaryCard { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#scanSummaryCard QLabel { border: none; background: transparent; }"
            "QFrame#scanDetailActionBar { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#scanDetailActionBar QLabel { border: none; background: transparent; }"));
        tabs_->addTab(detectionsPanel_, tr("Results (0)"));
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
    }

private:
    void updateStatusCard()
    {
        const bool running = !finished_;
        const int pending = std::count_if(detectedFiles_.cbegin(), detectedFiles_.cend(),
                                          [](const DetectionEntry &entry) {
                                              return !entry.handled && !entry.deleted;
                                          });
        const bool allHandled = infectionDetected_ && !detectedFiles_.isEmpty() && pending == 0;
        const QColor blue(60, 145, 220);
        const QColor red(210, 55, 65);
        const QColor green(80, 170, 100);
        QColor color = green;
        QString title = tr("Scan complete");
        QString details = tr("No threats were found.");
        if (running && infectionDetected_) {
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
    }

    static QString friendlyActivity(const QString &raw)
    {
        QStringList lines;
        for (const QString &sourceLine : raw.split(QLatin1Char('\n'))) {
            const QString line = sourceLine.trimmed();
            if (line.isEmpty())
                continue;
            if (line.startsWith(QStringLiteral("No viruses found."))) {
                continue;
            } else if (line.startsWith(QStringLiteral("A virus was identified."))) {
                lines << QStringLiteral("⚠  Threat detected");
            } else if (line.startsWith(QStringLiteral("Quarantined:"))) {
                lines << QStringLiteral("↪  Threat moved to quarantine");
            } else if (line.startsWith(QStringLiteral("Quarantine failed"))) {
                lines << QStringLiteral("⚠  Threat found, but quarantine failed");
            } else if (line.startsWith(QStringLiteral("SHA-256:"))
                       || line.startsWith(QStringLiteral("Scanner:"))
                       || line.startsWith(QStringLiteral("SCAN_FILE: "))
                       || line.contains(QStringLiteral("FILDES"))) {
                continue;
            } else {
                const QRegularExpression descriptor(QStringLiteral("^fd\\[\\d+\\]:\\s*(.+)$"));
                const auto match = descriptor.match(line);
                if (match.hasMatch() && match.captured(1).compare(QStringLiteral("OK"), Qt::CaseInsensitive) == 0)
                    continue;
                if (match.hasMatch() && match.captured(1).endsWith(QStringLiteral(" FOUND"), Qt::CaseInsensitive)) {
                    lines << tr("⚠  Threat detected: %1").arg(match.captured(1).left(match.captured(1).size() - 6).trimmed());
                    continue;
                }
            }
            if (line.endsWith(QStringLiteral(" FOUND"), Qt::CaseInsensitive)) {
                const QString path = line.left(line.indexOf(QStringLiteral(" FOUND"))).trimmed();
                lines << tr("⚠  Threat detected: %1")
                    .arg(QFileInfo(path.section(QLatin1Char(':'), 0, 0)).fileName());
            }
        }
        return lines.join(QLatin1Char('\n'));
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

    QLabel *addCard(QHBoxLayout *layout, const QString &title, const QString &value)
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
        cardLayout->addWidget(label);
        cardLayout->addWidget(valueLabel);
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

    qint64 processCpuTime() const
    {
        qint64 ticks = 0;
        for (const qint64 pid : pids_) {
            QFile stat(QStringLiteral("/proc/%1/stat").arg(pid));
            if (!stat.open(QIODevice::ReadOnly))
                return -1;
            const QByteArray contents = stat.readAll();
            const int closingParenthesis = contents.lastIndexOf(')');
            if (closingParenthesis < 0)
                return -1;
            const QList<QByteArray> fields = contents.mid(closingParenthesis + 1).simplified().split(' ');
            if (fields.size() < 13)
                return -1;
            bool okUser = false, okKernel = false;
            ticks += fields.at(11).toLongLong(&okUser) + fields.at(12).toLongLong(&okKernel);
            if (!okUser || !okKernel)
                return -1;
        }
        return ticks;
    }

    QPair<qint64, qint64> processIo() const
    {
        qint64 read = 0, write = 0;
        for (const qint64 pid : pids_) {
            QFile io(QStringLiteral("/proc/%1/io").arg(pid));
            if (!io.open(QIODevice::ReadOnly))
                return {-1, -1};
            while (!io.atEnd()) {
                const QList<QByteArray> fields = io.readLine().split(':');
                if (fields.size() != 2)
                    continue;
                bool ok = false;
                const qint64 value = fields.at(1).trimmed().toLongLong(&ok);
                if (ok && fields.at(0) == "read_bytes") read += value;
                if (ok && fields.at(0) == "write_bytes") write += value;
            }
        }
        return {read, write};
    }

    void readOutput()
    {
        const QByteArray text = process_->readAllStandardOutput() + process_->readAllStandardError();
        if (!text.isEmpty()) {
            const QString incoming = QString::fromLocal8Bit(text);
            for (const QString &sourceLine : incoming.split(QLatin1Char('\n'))) {
                const QString line = sourceLine.trimmed();
                if (line.startsWith(QStringLiteral("SCAN_FILE: ")))
                    currentFile_ = line.mid(QStringLiteral("SCAN_FILE: ").size());
                else if (line.startsWith(QStringLiteral("SCAN_RESULT: "))) {
                    const QJsonDocument document = QJsonDocument::fromJson(
                        line.mid(QStringLiteral("SCAN_RESULT: ").size()).toUtf8());
                    const QJsonObject result = document.object();
                    scanHashes_.insert(currentFile_, result.value(QStringLiteral("sha256")).toString());
                    if (result.value(QStringLiteral("infected")).toBool()) {
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
                        const bool known = std::any_of(detectedFiles_.cbegin(), detectedFiles_.cend(),
                            [this, &detection](const DetectionEntry &entry) {
                                return entry.path == currentFile_
                                    && entry.detection.compare(detection, Qt::CaseInsensitive) == 0;
                            });
                        if (!known)
                            detectedFiles_.append({currentFile_, detection, scanHashes_.value(currentFile_), {},
                                                   result.value(QStringLiteral("quarantined")).toBool(), false});
                        infectionDetected_ = true;
                    }
                }
                else if (line.startsWith(QStringLiteral("SHA-256: "))) {
                    const QString hash = line.mid(QStringLiteral("SHA-256: ").size()).trimmed();
                    scanHashes_.insert(currentFile_, hash);
                    for (auto &entry : detectedFiles_)
                        if (entry.path == currentFile_)
                            entry.sha256 = hash;
                }
            }
            rawOutput_ += incoming;
            for (const QString &sourceLine : rawOutput_.split(QLatin1Char('\n'))) {
                const QString line = sourceLine.trimmed();
                if (line.startsWith(QStringLiteral("SCAN_RESULT: ")))
                    continue;
                if (line.startsWith(QStringLiteral("Quarantined: "), Qt::CaseInsensitive)) {
                    const QString path = line.mid(QStringLiteral("Quarantined: ").size()).trimmed();
                    for (auto &entry : detectedFiles_)
                        if (entry.path == path)
                            entry.handled = true;
                }
            }
            refreshDetectionsPanel();
            updateStatusCard();
            output_->setPlainText(friendlyActivity(rawOutput_));
            output_->ensureCursorVisible();
        }
    }

    void updateQueue()
    {
        const Stats stats = queryStats(socketPath_);
        if (!stats.valid) {
            queueStatus_->setText(tr("Unavailable"));
            return;
        }
        queueStatus_->setText(tr("%1 queued · %2/%3 threads · %4 MiB")
            .arg(stats.queue).arg(stats.live + stats.idle).arg(stats.maximum).arg(stats.memory, 0, 'f', 1));
    }

    void refreshDetectionsPanel()
    {
        if (!detectionsList_)
            return;
        QString selectedPath;
        QString selectedDetection;
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
        if (tabs_)
            tabs_->setTabText(1, tr("Results (%1)").arg(count));
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
        detailPath_->setText(tr("Path: %1").arg(QDir::toNativeSeparators(entry->path)));
        detailHash_->setText(entry->sha256.isEmpty() ? tr("SHA-256: unavailable")
                                                      : tr("SHA-256: %1").arg(entry->sha256));
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
            detailStatusIcon_->setText(QString());
            detailStatusIcon_->setPixmap(statusIcon.pixmap(QSize(40, 40)));
        } else {
            detailStatusIcon_->setPixmap(QPixmap());
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
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - started_).count();
        const qint64 cpu = processCpuTime();
        const auto io = processIo();
        if (cpu >= 0 && cpuSample_ >= 0 && elapsed - sampleTime_ > 0) {
            const double usage = std::max(0.0, (cpu - cpuSample_) / 100.0 / (elapsed - sampleTime_));
            cpuPeak_ = std::max(cpuPeak_, usage);
            cpuSeconds_ += std::max(0.0, (cpu - cpuSample_) / 100.0);
            cpuStatus_->setText(tr("%1: %2%").arg(cpuTarget_).arg(usage, 0, 'f', 1));
        }
        if (io.first >= 0 && ioSample_.first >= 0 && elapsed - sampleTime_ > 0) {
            const double rate = (io.first - ioSample_.first + io.second - ioSample_.second) / (elapsed - sampleTime_);
            ioTotalRead_ += std::max<qint64>(0, io.first - ioSample_.first);
            ioTotalWrite_ += std::max<qint64>(0, io.second - ioSample_.second);
            ioPeak_ = std::max(ioPeak_, rate);
            ioStatus_->setText(tr("%1/s").arg(formatBytes(rate)));
        }
        cpuSample_ = cpu;
        ioSample_ = io;
        sampleTime_ = elapsed;
    }

    void cancelOrClose()
    {
        if (!confirmCloseWithUnhandledInfections())
            return;
        if (finished_) {
            accept();
            return;
        }
        cancelled_ = true;
        action_->setEnabled(false);
        process_->terminate();
        QTimer::singleShot(1500, this, [this] {
            if (process_->state() != QProcess::NotRunning)
                process_->kill();
        });
    }

    void scanFinished(int exitCode)
    {
        readOutput();
        metricsTimer_.stop();
        statsTimer_.stop();
        fileDisplayTimer_.stop();
        updateMetrics();
        finished_ = true;
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
        if (exitCode == 1 && infectionDetected_ && !detectedFiles_.isEmpty() && tabs_)
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
        ioStatus_->setText(tr("read %1 · write %2 · peak %3/s")
            .arg(formatBytes(ioTotalRead_)).arg(formatBytes(ioTotalWrite_)).arg(formatBytes(ioPeak_)));
        output_->ensureCursorVisible();
    }

    void closeEvent(QCloseEvent *event) override
    {
        if (!confirmCloseWithUnhandledInfections()) {
            event->ignore();
            return;
        }
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
        warning.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        warning.setDefaultButton(QMessageBox::No);
        return warning.exec() == QMessageBox::Yes;
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
        refreshDetectionsPanel();
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
        const QByteArray sha256 = detected.sha256.toLatin1();
        const QByteArray component = "plasma";
        const clamav_quarantine_metadata metadata{
            component.constData(), name.constData(), source.constData(),
            detection.constData(), sha256.constData()};
        char id[CLAMAV_QUARANTINE_ID_LENGTH];
        char payload[PATH_MAX];
        if (!clamav_quarantine_store(source.constData(), &metadata, 1, id, payload))
            return false;
        detected.handled = true;
        detected.quarantineId = QString::fromLatin1(id);
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
        refreshDetectionsPanel();
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
        refreshDetectionsPanel();
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
        refreshDetectionsPanel();
        updateStatusCard();
    }

    QString scanner_;
    QStringList paths_;
    bool quarantine_ = false;
    QString socketPath_;
    QString cpuTarget_ = tr("Scanner");
    QString statusText_;
    QString rawOutput_;
    QList<DetectionEntry> detectedFiles_;
    QHash<QString, QString> scanHashes_;
    QString currentFile_;
    QList<qint64> pids_;
    QProcess *process_ = nullptr;
    QLabel *queueStatus_ = nullptr;
    QLabel *cpuStatus_ = nullptr;
    QLabel *ioStatus_ = nullptr;
    QLabel *statusIcon_ = nullptr;
    QLabel *summary_ = nullptr;
    QLabel *targetSummary_ = nullptr;
    QLabel *currentFileLabel_ = nullptr;
    QFrame *statusCard_ = nullptr;
    QLabel *statusCardTitle_ = nullptr;
    QLabel *statusCardDetails_ = nullptr;
    QPushButton *openQuarantineButton_ = nullptr;
    QPushButton *quarantineButton_ = nullptr;
    QCheckBox *quarantineCheckBox_ = nullptr;
    QTabWidget *tabs_ = nullptr;
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
    QLabel *detailStatusIcon_ = nullptr;
    QPushButton *lookupButton_ = nullptr;
    QPushButton *virusTotalButton_ = nullptr;
    QPushButton *detailsToggleButton_ = nullptr;
    QPushButton *detailQuarantineButton_ = nullptr;
    QPushButton *detailDeleteButton_ = nullptr;
    QPushButton *detailQuarantineAllButton_ = nullptr;
    QPushButton *detailDeleteAllButton_ = nullptr;
    QProgressBar *progress_ = nullptr;
    QTextEdit *output_ = nullptr;
    QPushButton *action_ = nullptr;
    QTimer metricsTimer_, statsTimer_, fileDisplayTimer_;
    QTimer pulseTimer_;
    std::chrono::steady_clock::time_point started_;
    qint64 cpuSample_ = -1;
    QPair<qint64, qint64> ioSample_ = {-1, -1};
    double sampleTime_ = 0.0, cpuSeconds_ = 0.0, cpuPeak_ = 0.0, ioPeak_ = 0.0;
    qint64 ioTotalRead_ = 0, ioTotalWrite_ = 0;
    bool cancelled_ = false, finished_ = false, infectionDetected_ = false, pulseOn_ = false;
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
    if ((!parser.isSet(scannerOption) && !parser.isSet(quarantineOption)) || paths.isEmpty())
        return 2;
    QString scanner = QStandardPaths::findExecutable(QStringLiteral("clamav-scan-quarantine-helper"));
    if (scanner.isEmpty())
        return 2;
    ScanDialog dialog(scanner, paths, parser.isSet(quarantineOption));
    dialog.exec();
    return dialog.resultCode();
}
