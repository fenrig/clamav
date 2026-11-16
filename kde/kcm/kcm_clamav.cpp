#include <KLocalizedString>
#include <KCModule>
#include <KPluginFactory>

#include "quarantine.h"

#include <QCheckBox>
#include <QColor>
#include <QFile>
#include <QFileSystemWatcher>
#include <QFileInfo>
#include <QDir>
#include <QHash>
#include <QFormLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QLocalSocket>
#include <QMessageBox>
#include <QProcess>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QToolButton>
#include <QLocale>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QTabWidget>
#include <QTextStream>
#include <QRegularExpression>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const QString configDir = QStringLiteral(CLAMAV_CONF_DIR);
const QString dataDir = QStringLiteral(CLAMAV_DATA_DIR);
const QString helper = QStringLiteral(CLAMAV_LIBEXEC_DIR) + QStringLiteral("/clamav-kcm-helper");

QString databaseDirectory()
{
    QString directory = dataDir;
    QFile input(configDir + QStringLiteral("/clamd.conf"));
    if (input.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&input);
        while (!stream.atEnd()) {
            const QString line = stream.readLine().trimmed();
            if (line.startsWith(QStringLiteral("DatabaseDirectory "))) {
                directory = line.section(QLatin1Char(' '), 1).trimmed();
                break;
            }
        }
    }
    return directory;
}

QDateTime databaseLastModified()
{
    const QFileInfoList files = QDir(databaseDirectory()).entryInfoList(
        {QStringLiteral("main.*"), QStringLiteral("daily.*"), QStringLiteral("bytecode.*")},
        QDir::Files, QDir::Time);
    return files.isEmpty() ? QDateTime() : files.first().lastModified();
}

QString serviceState(const QString &unit)
{
    QProcess process;
    process.start(QStringLiteral("systemctl"), {QStringLiteral("is-active"), unit});
    process.waitForFinished(2000);
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

QString serviceEnabled(const QString &unit)
{
    QProcess process;
    process.start(QStringLiteral("systemctl"), {QStringLiteral("is-enabled"), unit});
    process.waitForFinished(2000);
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

QString userServiceState(const QString &unit)
{
    QProcess process;
    process.start(QStringLiteral("systemctl"), {QStringLiteral("--user"), QStringLiteral("is-active"), unit});
    process.waitForFinished(2000);
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

QString userServiceEnabled(const QString &unit)
{
    QProcess process;
    process.start(QStringLiteral("systemctl"), {QStringLiteral("--user"), QStringLiteral("is-enabled"), unit});
    process.waitForFinished(2000);
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

bool userSystemctl(const QStringList &arguments)
{
    QProcess process;
    process.start(QStringLiteral("systemctl"), QStringList{QStringLiteral("--user")} + arguments);
    return process.waitForFinished(10000) && process.exitCode() == 0;
}

QString systemdProperty(const QString &unit, const QString &property)
{
    QProcess process;
    process.start(QStringLiteral("systemctl"), {QStringLiteral("show"), QStringLiteral("--value"),
                                                  QStringLiteral("--property=") + property, unit});
    process.waitForFinished(2000);
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

QString socketPath()
{
    const QStringList files = {configDir + QStringLiteral("/clamd.conf"),
        QStringLiteral("/etc/clamd.conf"), QStringLiteral("/etc/clamd.d/scan.conf")};
    for (const QString &file : files) {
        QFile input(file);
        if (!input.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;
        QTextStream stream(&input);
        while (!stream.atEnd()) {
            const QString line = stream.readLine();
            if (line.startsWith(QStringLiteral("LocalSocket ")))
                return line.section(QLatin1Char(' '), 1).trimmed();
        }
    }
    return QStringLiteral("/run/clamav/clamd.ctl");
}

QString clamdCommand(const QByteArray &command)
{
    QLocalSocket socket;
    socket.connectToServer(socketPath());
    if (!socket.waitForConnected(500))
        return {};
    socket.write(command);
    socket.flush();
    if (!socket.waitForReadyRead(1000))
        return {};
    return QString::fromUtf8(socket.readAll());
}

QString databaseInfo()
{
    const QString directory = databaseDirectory();
    const QFileInfoList files = QDir(directory).entryInfoList(
        {QStringLiteral("main.*"), QStringLiteral("daily.*"), QStringLiteral("bytecode.*")},
        QDir::Files, QDir::Name);
    if (files.isEmpty())
        return i18n("Unavailable (%1)", directory);
    QStringList descriptions;
    for (const QFileInfo &file : files)
        descriptions << i18n("%1 (%2, %3)", file.fileName(),
                              QLocale().formattedDataSize(file.size()),
                              QLocale().toString(file.lastModified(), QLocale::ShortFormat));
    return i18n("%1 — %2", directory, descriptions.join(QStringLiteral(", ")));
}

QString databaseUpdated()
{
    const QString directory = databaseDirectory();
    const QFileInfoList files = QDir(directory).entryInfoList(
        {QStringLiteral("main.*"), QStringLiteral("daily.*"), QStringLiteral("bytecode.*")},
        QDir::Files, QDir::Time);
    return files.isEmpty() ? QString() : QLocale().toString(files.first().lastModified(), QLocale::ShortFormat);
}

bool databaseAvailable()
{
    const QString directory = databaseDirectory();
    return !QDir(directory).entryInfoList(
        {QStringLiteral("main.*"), QStringLiteral("daily.*"), QStringLiteral("bytecode.*")},
        QDir::Files).isEmpty();
}

QString friendlyStats(const QString &raw)
{
    QStringList lines;
    QRegularExpressionMatch match = QRegularExpression(QStringLiteral("^QUEUE:\\s*(\\d+)\\s+items"),
        QRegularExpression::MultilineOption).match(raw);
    if (match.hasMatch())
        lines << i18n("Queue: %1 item(s)", match.captured(1));
    match = QRegularExpression(QStringLiteral("^THREADS:\\s+live\\s+(\\d+)\\s+idle\\s+(\\d+)\\s+max\\s+(\\d+)"),
        QRegularExpression::MultilineOption).match(raw);
    if (match.hasMatch())
        lines << i18n("Workers: %1 active, %2 idle (maximum %3)", match.captured(1), match.captured(2), match.captured(3));
    match = QRegularExpression(QStringLiteral("^MEMSTATS:.*?heap\\s+([\\d.]+)M.*?mmap\\s+([\\d.]+)M.*?pools_total\\s+([\\d.]+)M"),
        QRegularExpression::MultilineOption).match(raw);
    if (match.hasMatch()) {
        const double memory = match.captured(1).toDouble() + match.captured(2).toDouble() + match.captured(3).toDouble();
        lines << i18n("Memory: %1 MiB", QString::number(memory, 'f', 1));
    }
    return lines.isEmpty() ? i18n("No live statistics available") : lines.join(QStringLiteral("\n"));
}

int quarantineLevel(const char *detection)
{
    const QString name = QString::fromLocal8Bit(detection).section('\n', 0, 0)
        .section(QStringLiteral(": "), -1).trimmed();
    if (name.startsWith(QStringLiteral("Eicar"), Qt::CaseInsensitive))
        return 1;
    if (name.startsWith(QStringLiteral("PUA."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("PUP."), Qt::CaseInsensitive))
        return 2;
    if (name.startsWith(QStringLiteral("Phishing."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("Heuristics."), Qt::CaseInsensitive))
        return 3;
    return 4;
}

QHash<QString, QStringList> parseConfig(const QString &fileName)
{
    QHash<QString, QStringList> values;
    QFile input(fileName);
    if (!input.open(QIODevice::ReadOnly | QIODevice::Text))
        return values;

    QTextStream stream(&input);
    const QRegularExpression setting(QStringLiteral("^\\s*([^#\\s]+)\\s+(.+?)\\s*$"));
    while (!stream.atEnd()) {
        const QString line = stream.readLine();
        const QRegularExpressionMatch match = setting.match(line);
        if (match.hasMatch())
            values[match.captured(1)] << match.captured(2).trimmed();
    }
    return values;
}
}

class ClamavKCM final : public KCModule
{
    Q_OBJECT
public:
    explicit ClamavKCM(QObject *parent, const KPluginMetaData &data)
        : KCModule(qobject_cast<QWidget *>(parent), data)
    {
        KLocalizedString::setApplicationDomain("kcm_clamav");
        auto *root = new QVBoxLayout(widget());
        root->setSpacing(16);
        widget()->setStyleSheet(QStringLiteral(
            "QGroupBox { color: palette(window-text); }"
            "QGroupBox QLabel { color: palette(window-text); }"
            "QPlainTextEdit { color: palette(text); background-color: palette(base); }"));
        auto *header = new QWidget(widget());
        auto *headerLayout = new QHBoxLayout(header);
        headerLayout->setContentsMargins(0, 0, 0, 0);
        auto *headerIcon = new QLabel(header);
        headerIcon->setPixmap(QIcon::fromTheme(QStringLiteral("clamav")).pixmap(48, 48));
        headerIcon->setFixedSize(56, 56);
        headerIcon->setAlignment(Qt::AlignCenter);
        headerLayout->addWidget(headerIcon);
        auto *headerText = new QVBoxLayout;
        auto *title = new QLabel(i18n("ClamAV protection"), header);
        title->setStyleSheet(QStringLiteral("font-size: 22px; font-weight: 600; color: palette(window-text);"));
        auto *subtitle = new QLabel(i18n("Manage malware scanning, on-access protection, and virus database updates."), header);
        subtitle->setWordWrap(true);
        subtitle->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        headerText->addWidget(title);
        headerText->addWidget(subtitle);
        headerLayout->addLayout(headerText, 1);
        root->addWidget(header);

        auto *tabs = new QTabWidget(widget());
        auto *overviewPage = new QWidget(tabs);
        auto *overviewLayout = new QVBoxLayout(overviewPage);
        auto *scanningPage = new QWidget(tabs);
        auto *scanningLayout = new QVBoxLayout(scanningPage);
        auto *updatesPage = new QWidget(tabs);
        auto *updatesLayout = new QVBoxLayout(updatesPage);
        auto *quarantinePage = new QWidget(tabs);
        auto *quarantineLayout = new QVBoxLayout(quarantinePage);
        auto *auditPage = new QWidget(tabs);
        auto *auditLayout = new QVBoxLayout(auditPage);
        tabs->addTab(overviewPage, QIcon::fromTheme(QStringLiteral("view-dashboard")), i18n("Overview"));
        tabs->addTab(scanningPage, QIcon::fromTheme(QStringLiteral("security-high")), i18n("Scanning"));
        tabs->addTab(updatesPage, QIcon::fromTheme(QStringLiteral("system-software-update")), i18n("Updates"));
        tabs->addTab(quarantinePage, QIcon::fromTheme(QStringLiteral("clamav-quarantine")), i18n("Quarantine"));
        tabs->addTab(auditPage, QIcon::fromTheme(QStringLiteral("security-high")), i18n("Security audit"));
        root->addWidget(tabs, 1);

        healthBanner = new QFrame(widget());
        healthBanner->setObjectName(QStringLiteral("healthBanner"));
        auto *healthLayout = new QHBoxLayout(healthBanner);
        healthLayout->setContentsMargins(16, 12, 16, 12);
        healthIcon = new QLabel(healthBanner);
        healthIcon->setFixedSize(32, 32);
        healthIcon->setAlignment(Qt::AlignCenter);
        healthLayout->addWidget(healthIcon);
        auto *healthText = new QVBoxLayout;
        healthTitle = new QLabel(healthBanner);
        healthTitle->setStyleSheet(QStringLiteral("font-size: 17px; font-weight: 600; color: palette(window-text);"));
        healthDetails = new QLabel(healthBanner);
        healthDetails->setWordWrap(true);
        healthDetails->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        healthText->addWidget(healthTitle);
        healthText->addWidget(healthDetails);
        healthLayout->addLayout(healthText, 1);
        healthAction = new QPushButton(healthBanner);
        healthAction->setIcon(QIcon::fromTheme(QStringLiteral("go-next")));
        connect(healthAction, &QPushButton::clicked, this, [this, tabs] {
            if (healthActionType == 1)
                startDaemon();
            else if (healthActionType == 2)
                setupFreshclam();
            else if (healthActionType == 3)
                enableOnAccess();
            else if (healthActionType == 4)
                openQuarantine();
            else
                tabs->setCurrentIndex(0);
        });
        healthLayout->addWidget(healthAction);
        overviewLayout->addWidget(healthBanner);

        auto *overview = new QGridLayout;
        overview->setHorizontalSpacing(10);
        overview->setVerticalSpacing(10);
        const auto addOverviewCard = [overview](const QString &title, int row, int column,
                                                QFrame **cardOutput, QLabel **valueOutput,
                                                QPushButton **actionOutput, const QString &actionText) {
            auto *card = new QFrame;
            card->setObjectName(QStringLiteral("overviewCard"));
            auto *cardLayout = new QVBoxLayout(card);
            cardLayout->setContentsMargins(14, 12, 14, 12);
            auto *heading = new QLabel(title, card);
            heading->setStyleSheet(QStringLiteral("font-weight: 600; color: palette(window-text);"));
            auto *value = new QLabel(card);
            value->setWordWrap(true);
            value->setStyleSheet(QStringLiteral("font-size: 15px; font-weight: 600; color: palette(window-text);"));
            cardLayout->addWidget(heading);
            cardLayout->addWidget(value);
            QPushButton *action = nullptr;
            if (!actionText.isEmpty()) {
                action = new QPushButton(actionText, card);
                action->setIcon(QIcon::fromTheme(QStringLiteral("go-next")));
                action->setVisible(false);
                cardLayout->addWidget(action);
            }
            overview->addWidget(card, row, column);
            *cardOutput = card;
            *valueOutput = value;
            if (actionOutput)
                *actionOutput = action;
            return value;
        };
        addOverviewCard(i18n("Antivirus"), 0, 0, &engineCard, &engineOverview, &engineAction, i18n("Start service"));
        addOverviewCard(i18n("Database updates"), 0, 1, &updatesCard, &updatesOverview, &updatesAction, i18n("Set up updates"));
        addOverviewCard(i18n("Virus database"), 0, 2, &databaseCard, &databaseOverview, &databaseAction, i18n("Update now"));
        addOverviewCard(i18n("On-access protection"), 1, 0, &onAccessCard, &onAccessOverview, &onAccessAction, i18n("Enable protection"));
        addOverviewCard(i18n("Quarantine"), 1, 1, &quarantineCard, &quarantineOverview, &quarantineAction, i18n("Open quarantine"));
        auto *overviewSpacer = new QWidget(widget());
        overviewSpacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        overview->addWidget(overviewSpacer, 1, 2);
        overviewLayout->addLayout(overview);
        connect(engineAction, &QPushButton::clicked, this, &ClamavKCM::startDaemon);
        connect(updatesAction, &QPushButton::clicked, this, &ClamavKCM::setupFreshclam);
        connect(databaseAction, &QPushButton::clicked, this, &ClamavKCM::updateDatabaseNow);
        connect(onAccessAction, &QPushButton::clicked, this, &ClamavKCM::enableOnAccess);
        connect(quarantineAction, &QPushButton::clicked, this, &ClamavKCM::openQuarantine);

        recommendedScans = new QGroupBox(i18n("Recommended scans"), overviewPage);
        recommendedScansLayout = new QGridLayout(recommendedScans);
        overviewLayout->addWidget(recommendedScans);

        auto *statusBox = new QGroupBox(i18n("System details"), widget());
        auto *status = new QFormLayout(statusBox);
        clamdStatus = new QLabel;
        freshclamStatus = new QLabel;
        onAccessStatus = new QLabel;
        timerStatus = new QLabel;
        databaseStatus = new QLabel;
        for (QLabel *label : {clamdStatus, freshclamStatus, onAccessStatus, timerStatus, databaseStatus})
            label->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        stats = new QPlainTextEdit;
        stats->setReadOnly(true);
        stats->setMaximumHeight(150);
        stats->setLineWrapMode(QPlainTextEdit::NoWrap);
        status->addRow(i18n("Antivirus service:"), clamdStatus);
        status->addRow(i18n("Database updater:"), freshclamStatus);
        status->addRow(i18n("On-access protection:"), onAccessStatus);
        status->addRow(i18n("Update schedule:"), timerStatus);
        status->addRow(i18n("Virus database:"), databaseStatus);
        status->addRow(i18n("Scanner workload:"), stats);
        overviewLayout->addWidget(statusBox);

        auto *actions = new QGroupBox(i18n("Quick actions"), widget());
        auto *actionLayout = new QGridLayout(actions);
        actionLayout->setHorizontalSpacing(8);
        actionLayout->setVerticalSpacing(8);
        auto *quarantine = new QPushButton(i18n("Open quarantine"), actions);
        quarantine->setIcon(QIcon::fromTheme(QStringLiteral("folder-open")));
        connect(quarantine, &QPushButton::clicked, this, &ClamavKCM::openQuarantine);
        addButton(actionLayout, quarantine);
        auto *scanCommon = new QPushButton(i18n("Scan home folders"), actions);
        scanCommon->setIcon(QIcon::fromTheme(QStringLiteral("security-high")));
        connect(scanCommon, &QPushButton::clicked, this, &ClamavKCM::scanCommonFolders);
        addButton(actionLayout, scanCommon);
        auto *scanRemovable = new QPushButton(i18n("Scan removable media"), actions);
        scanRemovable->setIcon(QIcon::fromTheme(QStringLiteral("drive-removable-media")));
        connect(scanRemovable, &QPushButton::clicked, this, &ClamavKCM::scanRemovableMedia);
        addButton(actionLayout, scanRemovable);
        auto *refresh = new QPushButton(i18n("Refresh"), actions);
        refresh->setIcon(QIcon::fromTheme(QStringLiteral("view-refresh")));
        connect(refresh, &QPushButton::clicked, this, &ClamavKCM::refreshStatus);
        addButton(actionLayout, refresh);
        applyButton = new QPushButton(i18n("Apply configuration"), actions);
        applyButton->setIcon(QIcon::fromTheme(QStringLiteral("dialog-ok-apply")));
        applyButton->setEnabled(false);
        connect(applyButton, &QPushButton::clicked, this, &ClamavKCM::save);
        addButton(actionLayout, applyButton);
        overviewLayout->addWidget(actions);

        auto *settings = new QGroupBox(i18n("Scanner configuration"), scanningPage);
        auto *settingsLayout = new QVBoxLayout(settings);
        auto *settingsIntro = new QLabel(i18n("These options control how ClamAV scans files and how often its virus database is refreshed."), settings);
        settingsIntro->setWordWrap(true);
        settingsIntro->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        settingsLayout->addWidget(settingsIntro);
        auto *form = new QFormLayout;
        settingsLayout->addLayout(form);
        lazyLoading = new QCheckBox(i18n("Load the database on demand"), settings);
        keepAlive = new QLineEdit(settings);
        heuristicAlerts = new QCheckBox(i18n("Enable heuristic alerts"), settings);
        heuristicPrecedence = new QCheckBox(i18n("Give heuristic detections precedence"), settings);
        onAccessPrevention = new QCheckBox(i18n("Enable on-access prevention"), settings);
        pathEditor = new QWidget(settings);
        pathLayout = new QVBoxLayout(pathEditor);
        pathLayout->setContentsMargins(0, 0, 0, 0);
        auto *addPath = new QPushButton(i18n("Add path"), pathEditor);
        connect(addPath, &QPushButton::clicked, this, [this] { addPathRow(); });
        pathLayout->addWidget(addPath);
        form->addRow(lazyLoading);
        form->addRow(i18n("Database keep-alive:"), keepAlive);
        form->addRow(heuristicAlerts);
        form->addRow(heuristicPrecedence);
        form->addRow(onAccessPrevention);
        form->addRow(i18n("On-access include paths:"), pathEditor);
        auto *updates = new QGroupBox(i18n("Virus database updates"), updatesPage);
        auto *updatesForm = new QFormLayout(updates);
        auto *updatesIntro = new QLabel(i18n("Keep the virus database current so new threats can be detected."), updates);
        updatesIntro->setWordWrap(true);
        updatesIntro->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        updatesForm->addRow(updatesIntro);
        freshclamSchedule = new QLineEdit(updates);
        freshclamSchedule->setPlaceholderText(i18n("For example: daily or Mon *-*-* 03:00:00"));
        freshclamDelay = new QLineEdit(updates);
        freshclamDelay->setPlaceholderText(i18n("For example: 1h or 15min"));
        updatesForm->addRow(i18n("Update schedule:"), freshclamSchedule);
        updatesForm->addRow(i18n("Randomized delay:"), freshclamDelay);
        quarantineRetention = new QSpinBox(quarantinePage);
        quarantineRetention->setRange(0, 3650);
        quarantineRetention->setSuffix(i18n(" days (0 disables cleanup)"));
        scanningLayout->addWidget(settings);
        auto *serviceControls = new QGroupBox(i18n("Advanced service controls"), scanningPage);
        auto *serviceLayout = new QGridLayout(serviceControls);
        addAction(serviceLayout, i18n("Reload daemon"), "reload", "clamav-daemon.service");
        addAction(serviceLayout, i18n("Restart daemon"), "restart", "clamav-daemon.service");
        addAction(serviceLayout, i18n("Enable daemon"), "enable", "clamav-daemon.service");
        addAction(serviceLayout, i18n("Disable daemon"), "disable", "clamav-daemon.service");
        addAction(serviceLayout, i18n("Start on-access"), "start", "clamav-clamonacc.service");
        addAction(serviceLayout, i18n("Enable on-access"), "enable", "clamav-clamonacc.service");
        addAction(serviceLayout, i18n("Disable on-access"), "disable", "clamav-clamonacc.service");
        scanningLayout->addWidget(serviceControls);
        scanningLayout->addStretch();
        updatesLayout->addWidget(updates);
        auto *updateControls = new QGroupBox(i18n("Update controls"), updatesPage);
        auto *updateLayout = new QGridLayout(updateControls);
        addAction(updateLayout, i18n("Update database now"), "start", "clamav-freshclam-once.service");
        addAction(updateLayout, i18n("Enable automatic updates"), "enable", "clamav-freshclam-once.timer");
        addAction(updateLayout, i18n("Disable automatic updates"), "disable", "clamav-freshclam-once.timer");
        updatesLayout->addWidget(updateControls);
        updatesLayout->addStretch();
        auto *quarantineSettings = new QGroupBox(i18n("Automatic cleanup"), quarantinePage);
        auto *quarantineForm = new QFormLayout(quarantineSettings);
        auto *quarantineIntro = new QLabel(i18n("A user-level systemd timer removes quarantined files after the retention period. It runs once a day and catches up after the computer has been off."), quarantineSettings);
        quarantineIntro->setWordWrap(true);
        quarantineIntro->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        quarantineForm->addRow(quarantineIntro);
        quarantineTimerEnabled = new QCheckBox(i18n("Enable automatic quarantine cleanup"), quarantineSettings);
        quarantineForm->addRow(quarantineTimerEnabled);
        quarantineForm->addRow(i18n("Keep quarantined files for:"), quarantineRetention);
        quarantineTimerStatus = new QLabel(quarantineSettings);
        quarantineTimerStatus->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        quarantineForm->addRow(i18n("Timer status:"), quarantineTimerStatus);
        quarantineLayout->addWidget(quarantineSettings);
        auto *quarantineControls = new QGroupBox(i18n("Quarantine manager"), quarantinePage);
        auto *quarantineControlsLayout = new QGridLayout(quarantineControls);
        auto *openQuarantineButton = new QPushButton(i18n("Open quarantine"), quarantineControls);
        openQuarantineButton->setIcon(QIcon::fromTheme(QStringLiteral("folder-open")));
        connect(openQuarantineButton, &QPushButton::clicked, this, &ClamavKCM::openQuarantine);
        quarantineControlsLayout->addWidget(openQuarantineButton, 0, 0);
        auto *cleanupNow = new QPushButton(i18n("Run cleanup now"), quarantineControls);
        cleanupNow->setIcon(QIcon::fromTheme(QStringLiteral("edit-clear")));
        connect(cleanupNow, &QPushButton::clicked, this, [this] {
            if (!userSystemctl({QStringLiteral("start"), QStringLiteral("clamav-quarantine-cleanup.service")}))
                QMessageBox::warning(widget(), i18n("ClamAV"), i18n("The quarantine cleanup could not be started."));
            refreshStatus();
        });
        quarantineControlsLayout->addWidget(cleanupNow, 0, 1);
        quarantineLayout->addWidget(quarantineControls);
        quarantineLayout->addStretch();
        auto *auditIntro = new QLabel(i18n("Security audits look for configuration weaknesses and signs associated with known rootkits. They complement ClamAV and do not prove that a system is clean."), auditPage);
        auditIntro->setWordWrap(true);
        auditIntro->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        auditLayout->addWidget(auditIntro);
        auto *auditTools = new QGroupBox(i18n("Available audit tools"), auditPage);
        auto *auditForm = new QFormLayout(auditTools);
        lynisStatus = new QLabel(auditTools);
        chkrootkitStatus = new QLabel(auditTools);
        runLynisButton = new QPushButton(i18n("Run Lynis audit"), auditTools);
        runLynisButton->setIcon(QIcon::fromTheme(QStringLiteral("security-high")));
        runChkrootkitButton = new QPushButton(i18n("Run chkrootkit check"), auditTools);
        runChkrootkitButton->setIcon(QIcon::fromTheme(QStringLiteral("security-low")));
        auditForm->addRow(i18n("Lynis:"), lynisStatus);
        auditForm->addRow(i18n("chkrootkit:"), chkrootkitStatus);
        auditForm->addRow(runLynisButton);
        auditForm->addRow(runChkrootkitButton);
        auditLayout->addWidget(auditTools);
        auditOutput = new QPlainTextEdit(auditPage);
        auditOutput->setReadOnly(true);
        auditOutput->setPlaceholderText(i18n("Audit results will appear here."));
        auditLayout->addWidget(auditOutput, 1);
        connect(runLynisButton, &QPushButton::clicked, this, [this] {
            runAudit(QStringLiteral("lynis"), {QStringLiteral("audit"), QStringLiteral("system"), QStringLiteral("--no-colors")}, i18n("Lynis"));
        });
        connect(runChkrootkitButton, &QPushButton::clicked, this, [this] {
            runAudit(QStringLiteral("chkrootkit"), {}, i18n("chkrootkit"));
        });
        connect(lazyLoading, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(keepAlive, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        connect(heuristicAlerts, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(heuristicPrecedence, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(onAccessPrevention, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(freshclamSchedule, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        connect(freshclamDelay, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        connect(quarantineRetention, qOverload<int>(&QSpinBox::valueChanged), this, &ClamavKCM::settingsChanged);
        connect(quarantineTimerEnabled, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        configWatcher = new QFileSystemWatcher(this);
        if (QFile::exists(configFile()))
            configWatcher->addPath(configFile());
        connect(configWatcher, &QFileSystemWatcher::fileChanged, this, &ClamavKCM::configurationChanged);
        statusTimer = new QTimer(this);
        statusTimer->setInterval(30000);
        connect(statusTimer, &QTimer::timeout, this, &ClamavKCM::refreshStatus);
        statusTimer->start();
        load();
        refreshStatus();
    }

    void load() override
    {
        const auto values = parseConfig(configFile());
        const auto value = [&values](const QString &key, const QString &fallback = {}) {
            return values.value(key).value(0, fallback);
        };
        const QSignalBlocker blocker1(lazyLoading);
        const QSignalBlocker blocker2(keepAlive);
        const QSignalBlocker blocker3(heuristicAlerts);
        const QSignalBlocker blocker4(heuristicPrecedence);
        const QSignalBlocker blocker5(onAccessPrevention);
        const QSignalBlocker blocker6(quarantineRetention);
        const QSignalBlocker blocker7(quarantineTimerEnabled);
        lazyLoading->setChecked(value(QStringLiteral("OnDemandDatabase")) == QStringLiteral("yes"));
        keepAlive->setText(value(QStringLiteral("DatabaseKeepAlive"), QStringLiteral("5m")));
        heuristicAlerts->setChecked(value(QStringLiteral("HeuristicAlerts"), QStringLiteral("yes")) != QStringLiteral("no"));
        heuristicPrecedence->setChecked(value(QStringLiteral("HeuristicScanPrecedence")) == QStringLiteral("yes"));
        onAccessPrevention->setChecked(value(QStringLiteral("OnAccessPrevention")) == QStringLiteral("yes"));
        unsigned int retention = CLAMAV_QUARANTINE_DEFAULT_RETENTION_DAYS;
        clamav_quarantine_get_retention_days(&retention);
        quarantineRetention->setValue(static_cast<int>(retention));
        const QString quarantineTimerState = userServiceEnabled(QStringLiteral("clamav-quarantine-cleanup.timer"));
        quarantineTimerEnabled->setChecked(quarantineTimerState != QStringLiteral("disabled")
            && quarantineTimerState != QStringLiteral("masked"));
        loadPaths(values.value(QStringLiteral("OnAccessIncludePath")));
        loadTimerSettings();
        pendingChanges = false;
        setNeedsSave(false);
        applyButton->setEnabled(false);
        if (QFile::exists(configFile()) && !configWatcher->files().contains(configFile()))
            configWatcher->addPath(configFile());
    }

    void save() override
    {
        if (!clamav_quarantine_set_retention_days(static_cast<unsigned int>(quarantineRetention->value()))) {
            QMessageBox::warning(widget(), i18n("ClamAV"), i18n("The quarantine retention setting could not be saved."));
            return;
        }
        const QString quarantineTimer = QStringLiteral("clamav-quarantine-cleanup.timer");
        if (!userSystemctl({QStringLiteral("daemon-reload")})) {
            QMessageBox::warning(widget(), i18n("ClamAV"), i18n("The user systemd manager could not be reloaded."));
            return;
        }
        const QString timerAction = quarantineTimerEnabled->isChecked() ? QStringLiteral("enable") : QStringLiteral("disable");
        if (!userSystemctl({timerAction, quarantineTimer}))
            return;
        if (quarantineTimerEnabled->isChecked())
            userSystemctl({QStringLiteral("start"), quarantineTimer});
        else
            userSystemctl({QStringLiteral("stop"), quarantineTimer});
        if (!runHelper({QStringLiteral("write-clamd"), QStringLiteral("OnDemandDatabase"), boolValue(lazyLoading)})) return;
        if (!runHelper({QStringLiteral("write-clamd"), QStringLiteral("DatabaseKeepAlive"), keepAlive->text()})) return;
        if (!runHelper({QStringLiteral("write-clamd"), QStringLiteral("HeuristicAlerts"), boolValue(heuristicAlerts)})) return;
        if (!runHelper({QStringLiteral("write-clamd"), QStringLiteral("HeuristicScanPrecedence"), boolValue(heuristicPrecedence)})) return;
        if (!runHelper({QStringLiteral("write-clamd"), QStringLiteral("OnAccessPrevention"), boolValue(onAccessPrevention)})) return;
        QStringList paths;
        for (QLineEdit *edit : std::as_const(pathEdits)) {
            const QString path = edit->text().trimmed();
            if (!path.isEmpty())
                paths << path;
        }
        if (!runHelper(QStringList{QStringLiteral("write-paths"), QStringLiteral("OnAccessIncludePath")} + paths)) return;
        if (!runHelper({QStringLiteral("timer-set"), freshclamSchedule->text().trimmed(), freshclamDelay->text().trimmed()})) return;
        if (!runHelper({QStringLiteral("service"), QStringLiteral("restart"), QStringLiteral("clamav-freshclam-once.timer")})) return;
        runHelper({QStringLiteral("service"), QStringLiteral("reload"), QStringLiteral("clamav-daemon.service")});
        setNeedsSave(false);
        pendingChanges = false;
        applyButton->setEnabled(false);
        refreshStatus();
    }

    void defaults() override
    {
        lazyLoading->setChecked(false);
        keepAlive->setText(QStringLiteral("5m"));
        heuristicAlerts->setChecked(true);
        heuristicPrecedence->setChecked(false);
        onAccessPrevention->setChecked(false);
        loadPaths({});
        freshclamSchedule->setText(QStringLiteral("daily"));
        freshclamDelay->setText(QStringLiteral("1h"));
        quarantineRetention->setValue(CLAMAV_QUARANTINE_DEFAULT_RETENTION_DAYS);
        quarantineTimerEnabled->setChecked(true);
        setNeedsSave(true);
        pendingChanges = true;
        applyButton->setEnabled(true);
    }

private:
    QFrame *healthBanner;
    QLabel *healthIcon, *healthTitle, *healthDetails;
    QPushButton *healthAction;
    int healthActionType = 0;
    QFrame *engineCard, *updatesCard, *databaseCard, *onAccessCard, *quarantineCard;
    QGroupBox *recommendedScans;
    QGridLayout *recommendedScansLayout;
    QLabel *engineOverview, *updatesOverview, *databaseOverview, *onAccessOverview, *quarantineOverview;
    QPushButton *engineAction, *updatesAction, *databaseAction, *onAccessAction, *quarantineAction;
    QLabel *clamdStatus, *freshclamStatus, *onAccessStatus, *timerStatus, *databaseStatus;
    QPlainTextEdit *stats;
    QCheckBox *lazyLoading, *heuristicAlerts, *heuristicPrecedence, *onAccessPrevention;
    QLineEdit *keepAlive;
    QLineEdit *freshclamSchedule, *freshclamDelay;
    QSpinBox *quarantineRetention;
    QCheckBox *quarantineTimerEnabled;
    QLabel *quarantineTimerStatus;
    QLabel *lynisStatus;
    QLabel *chkrootkitStatus;
    QPushButton *runLynisButton;
    QPushButton *runChkrootkitButton;
    QPlainTextEdit *auditOutput;
    QProcess *auditProcess = nullptr;
    QWidget *pathEditor;
    QVBoxLayout *pathLayout;
    QList<QLineEdit *> pathEdits;
    QFileSystemWatcher *configWatcher;
    QTimer *statusTimer;
    QPushButton *applyButton;
    bool pendingChanges = false;

    static QString boolValue(const QCheckBox *box) { return box->isChecked() ? QStringLiteral("yes") : QStringLiteral("no"); }
    QString configFile() const { return configDir + QStringLiteral("/clamd.conf"); }
    void loadTimerSettings()
    {
        const QSignalBlocker scheduleBlocker(freshclamSchedule);
        const QSignalBlocker delayBlocker(freshclamDelay);
        const QString schedule = systemdProperty(QStringLiteral("clamav-freshclam-once.timer"), QStringLiteral("OnCalendar"));
        const QString delay = systemdProperty(QStringLiteral("clamav-freshclam-once.timer"), QStringLiteral("RandomizedDelayUSec"));
        freshclamSchedule->setText(schedule.isEmpty() ? QStringLiteral("daily") : schedule);
        freshclamDelay->setText(delay.isEmpty() ? QStringLiteral("1h") : delay);
    }
    void settingsChanged()
    {
        pendingChanges = true;
        setNeedsSave(true);
        applyButton->setEnabled(true);
    }
    void addPathRow(const QString &path = {})
    {
        auto *row = new QWidget(pathEditor);
        auto *layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 0, 0, 0);
        auto *edit = new QLineEdit(path, row);
        edit->setPlaceholderText(i18n("Absolute directory path"));
        auto *remove = new QToolButton(row);
        remove->setText(QStringLiteral("−"));
        remove->setToolTip(i18n("Remove this path"));
        layout->addWidget(edit);
        layout->addWidget(remove);
        pathLayout->insertWidget(pathLayout->count() - 1, row);
        pathEdits << edit;
        connect(edit, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        connect(remove, &QToolButton::clicked, this, [this, row, edit] {
            pathEdits.removeOne(edit);
            row->deleteLater();
            settingsChanged();
        });
    }
    void loadPaths(const QStringList &paths)
    {
        for (QLineEdit *edit : std::as_const(pathEdits))
            edit->parentWidget()->deleteLater();
        pathEdits.clear();
        for (const QString &path : paths)
            addPathRow(path);
    }
    void configurationChanged(const QString &path)
    {
        if (!pendingChanges)
            load();
        if (QFile::exists(path) && !configWatcher->files().contains(path))
            configWatcher->addPath(path);
        refreshStatus();
    }
    void addAction(QGridLayout *layout, const QString &label, const QString &action, const QString &unit)
    {
        auto *button = new QPushButton(label, widget());
        connect(button, &QPushButton::clicked, this, [this, action, unit] { runHelper({QStringLiteral("service"), action, unit}); refreshStatus(); });
        addButton(layout, button);
    }
    static void addButton(QGridLayout *layout, QPushButton *button)
    {
        const int position = layout->count();
        button->setMinimumHeight(34);
        layout->addWidget(button, position / 3, position % 3);
    }
    static void setCardState(QFrame *card, const QColor &color)
    {
        card->setStyleSheet(QStringLiteral(
            "QFrame#overviewCard { background: rgba(%1, %2, %3, 42); border: 1px solid rgba(%1, %2, %3, 150); border-radius: 8px; }")
            .arg(color.red()).arg(color.green()).arg(color.blue()));
    }
    void setHealthIcon(const QString &name)
    {
        healthIcon->setPixmap(QIcon::fromTheme(name).pixmap(28, 28));
    }
    void startDaemon()
    {
        if (!runHelper({QStringLiteral("service"), QStringLiteral("enable"), QStringLiteral("clamav-daemon.service")}))
            return;
        runHelper({QStringLiteral("service"), QStringLiteral("start"), QStringLiteral("clamav-daemon.service")});
        refreshStatus();
    }
    void setupFreshclam()
    {
        if (!runHelper({QStringLiteral("initialize-freshclam")}))
            return;
        if (!runHelper({QStringLiteral("service"), QStringLiteral("enable"), QStringLiteral("clamav-freshclam-once.timer")}))
            return;
        runHelper({QStringLiteral("service"), QStringLiteral("start"), QStringLiteral("clamav-freshclam-once.timer")});
        refreshStatus();
    }
    void updateDatabaseNow()
    {
        if (!QFile::exists(configDir + QStringLiteral("/freshclam.conf")) && !runHelper({QStringLiteral("initialize-freshclam")}))
            return;
        const auto before = databaseLastModified();
        if (!runHelper({QStringLiteral("service"), QStringLiteral("start"), QStringLiteral("clamav-freshclam-once.service")}))
            return;
        const auto after = databaseLastModified();
        if (!after.isValid()) {
            QMessageBox::warning(widget(), i18n("ClamAV"),
                                 i18n("FreshClam completed, but no virus database is available."));
        } else if (!before.isValid() || after > before) {
            QMessageBox::information(widget(), i18n("ClamAV"),
                                     i18n("The virus database was updated."));
        } else {
            QMessageBox::information(widget(), i18n("ClamAV"),
                                     i18n("The virus database is already up to date."));
        }
        refreshStatus();
    }
    void enableOnAccess()
    {
        if (!runHelper({QStringLiteral("write-clamd"), QStringLiteral("OnAccessPrevention"), QStringLiteral("yes")}))
            return;
        if (!runHelper({QStringLiteral("service"), QStringLiteral("enable"), QStringLiteral("clamav-clamonacc.service")}))
            return;
        runHelper({QStringLiteral("service"), QStringLiteral("start"), QStringLiteral("clamav-clamonacc.service")});
        runHelper({QStringLiteral("service"), QStringLiteral("reload"), QStringLiteral("clamav-daemon.service")});
        load();
        refreshStatus();
    }
    void openQuarantine()
    {
        if (!QProcess::startDetached(QStringLiteral("clamav-quarantine-gui")))
            QMessageBox::warning(widget(), i18n("ClamAV"),
                                 i18n("The quarantine manager could not be opened."));
    }
    void updateAuditAvailability()
    {
        const QString lynis = QStandardPaths::findExecutable(QStringLiteral("lynis"));
        const QString chkrootkit = QStandardPaths::findExecutable(QStringLiteral("chkrootkit"));
        lynisStatus->setText(lynis.isEmpty() ? i18n("Not installed") : i18n("Installed (%1)", lynis));
        chkrootkitStatus->setText(chkrootkit.isEmpty() ? i18n("Not installed") : i18n("Installed (%1)", chkrootkit));
        runLynisButton->setEnabled(!lynis.isEmpty() && auditProcess == nullptr);
        runChkrootkitButton->setEnabled(!chkrootkit.isEmpty() && auditProcess == nullptr);
    }
    void runAudit(const QString &program, const QStringList &arguments, const QString &label)
    {
        if (auditProcess != nullptr)
            return;
        const QString executable = QStandardPaths::findExecutable(program);
        if (executable.isEmpty()) {
            QMessageBox::information(widget(), i18n("ClamAV"),
                                     i18n("%1 is not installed.", label));
            updateAuditAvailability();
            return;
        }
        auditOutput->setPlainText(i18n("Running %1…\n\nA privilege prompt may appear.", label));
        auditProcess = new QProcess(this);
        connect(auditProcess, &QProcess::readyReadStandardOutput, this, [this] {
            auditOutput->appendPlainText(QString::fromLocal8Bit(auditProcess->readAllStandardOutput()));
        });
        connect(auditProcess, &QProcess::readyReadStandardError, this, [this] {
            const QString error = QString::fromLocal8Bit(auditProcess->readAllStandardError());
            if (!error.isEmpty())
                auditOutput->appendPlainText(error);
        });
        connect(auditProcess, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this, label](int code, QProcess::ExitStatus status) {
            const QString output = auditOutput->toPlainText();
            auditOutput->setPlainText(output + QStringLiteral("\n\n")
                + (status == QProcess::NormalExit
                    ? i18n("%1 finished with exit code %2.", label, code)
                    : i18n("%1 terminated unexpectedly.", label)));
            auditProcess->deleteLater();
            auditProcess = nullptr;
            updateAuditAvailability();
        });
        auditProcess->start(QStringLiteral("pkexec"), QStringList{executable} + arguments);
        updateAuditAvailability();
    }
    static QStringList commonScanPaths()
    {
        QStringList paths;
        const QString home = QDir::homePath();
        if (home.isEmpty() || !QFileInfo(home).isDir())
            return paths;
        const QDir homeDirectory(home);
        for (const QFileInfo &entry : homeDirectory.entryInfoList(
                 QDir::Dirs | QDir::NoDotAndDotDot | QDir::Readable, QDir::Name))
            if (!entry.fileName().startsWith(QLatin1Char('.')))
                paths << entry.absoluteFilePath();
        return paths;
    }
    static QStringList removableScanPaths()
    {
        QStringList paths;
        for (const QStorageInfo &volume : QStorageInfo::mountedVolumes()) {
            if (!volume.isValid() || !volume.isReady() || volume.rootPath() == QStringLiteral("/"))
                continue;
            const QString device = QString::fromLocal8Bit(volume.device());
            if (!device.startsWith(QStringLiteral("/dev/")))
                continue;
            QFile removable(QStringLiteral("/sys/class/block/%1/removable")
                                .arg(QFileInfo(device).fileName()));
            if (!removable.open(QIODevice::ReadOnly) || removable.readAll().trimmed() != "1")
                continue;
            if (!paths.contains(volume.rootPath()))
                paths << volume.rootPath();
        }
        return paths;
    }
    void refreshRecommendedScans()
    {
        while (QLayoutItem *item = recommendedScansLayout->takeAt(0)) {
            if (QWidget *card = item->widget())
                card->deleteLater();
            delete item;
        }
        const auto addSuggestion = [this](const QString &title, const QString &description,
                                           const QStringList &paths, const QIcon &icon) {
            auto *card = new QFrame(recommendedScans);
            card->setObjectName(QStringLiteral("recommendedScanCard"));
            card->setStyleSheet(QStringLiteral(
                "QFrame#recommendedScanCard { background: rgba(80, 170, 100, 35); border: 1px solid rgba(80, 170, 100, 150); border-radius: 8px; }"
                "QFrame#recommendedScanCard QLabel { color: palette(window-text); border: none; background: transparent; }"));
            auto *cardLayout = new QVBoxLayout(card);
            auto *heading = new QLabel(title, card);
            heading->setStyleSheet(QStringLiteral("font-weight: 600; color: palette(window-text);"));
            auto *details = new QLabel(description, card);
            details->setWordWrap(true);
            details->setStyleSheet(QStringLiteral("color: palette(window-text);"));
            auto *scan = new QPushButton(i18n("Scan now"), card);
            scan->setIcon(icon);
            connect(scan, &QPushButton::clicked, this, [this, paths] {
                startQuarantineScan(paths, i18n("The selected scan target is no longer available."));
            });
            cardLayout->addWidget(heading);
            cardLayout->addWidget(details);
            cardLayout->addWidget(scan);
            const int index = recommendedScansLayout->count();
            recommendedScansLayout->addWidget(card, index / 2, index % 2);
        };
        addSuggestion(i18n("Home folders"),
                      i18n("Scan visible folders in your home directory. Hidden configuration folders are excluded."),
                      commonScanPaths(), QIcon::fromTheme(QStringLiteral("security-high")));
        const QStringList removable = removableScanPaths();
        for (const QString &path : removable) {
            const QStorageInfo volume(path);
            const QString title = volume.displayName().isEmpty()
                ? i18n("Removable media") : i18n("Removable media: %1", volume.displayName());
            addSuggestion(title,
                          i18n("Scan %1 recursively and quarantine detected threats on this computer.")
                              .arg(QDir::toNativeSeparators(path)),
                          QStringList{path}, QIcon::fromTheme(QStringLiteral("drive-removable-media")));
        }
        if (removable.isEmpty()) {
            auto *none = new QLabel(i18n("No removable media is currently mounted."), recommendedScans);
            none->setStyleSheet(QStringLiteral("color: palette(window-text);"));
            recommendedScansLayout->addWidget(none, 0, 1);
        }
    }
    void startQuarantineScan(const QStringList &paths, const QString &emptyMessage)
    {
        if (paths.isEmpty()) {
            QMessageBox::information(widget(), i18n("ClamAV"), emptyMessage);
            return;
        }
        if (!QProcess::startDetached(QStringLiteral("clamav-scan-gui"),
                                     QStringList{QStringLiteral("--quarantine")} + paths))
            QMessageBox::warning(widget(), i18n("ClamAV"),
                                 i18n("The scan dialog could not be started."));
    }
    void scanCommonFolders()
    {
        startQuarantineScan(commonScanPaths(),
                            i18n("No visible folders were found in the home directory."));
    }
    void scanRemovableMedia()
    {
        startQuarantineScan(removableScanPaths(),
                            i18n("No mounted removable media was found."));
    }
    bool runHelper(const QStringList &arguments)
    {
        const int result = QProcess::execute(QStringLiteral("pkexec"), QStringList{helper} + arguments);
        if (result != 0) {
            QMessageBox::warning(widget(), i18n("ClamAV"), i18n("The requested operation was not completed."));
            return false;
        }
        return true;
    }
    void refreshStatus()
    {
        refreshRecommendedScans();
        if (!pendingChanges)
            loadTimerSettings();
        const QString daemon = serviceState(QStringLiteral("clamav-daemon.service"));
        const QString freshclam = serviceState(QStringLiteral("clamav-freshclam.service"));
        const QString onAccess = serviceState(QStringLiteral("clamav-clamonacc.service"));
        const QString timer = serviceState(QStringLiteral("clamav-freshclam-once.timer"));
        const QString quarantineTimer = userServiceState(QStringLiteral("clamav-quarantine-cleanup.timer"));
        clamdStatus->setText(daemon == QStringLiteral("active") ? i18n("Running") : i18n("Stopped"));
        freshclamStatus->setText(freshclam == QStringLiteral("active") ? i18n("Running") : i18n("Not running"));
        onAccessStatus->setText(onAccessPrevention->isChecked()
            ? (onAccess == QStringLiteral("active") ? i18n("Running") : i18n("Configured but stopped"))
            : i18n("Disabled (optional)"));
        timerStatus->setText(timer == QStringLiteral("active") ? i18n("Scheduled") : i18n("Not scheduled"));
        quarantineTimerStatus->setText(quarantineTimer == QStringLiteral("active")
            ? i18n("Enabled and scheduled") : i18n("Disabled or not running"));
        databaseStatus->setText(databaseAvailable()
            ? i18n("Installed · last updated %1", databaseUpdated())
            : i18n("Unavailable"));
        const QString stat = clamdCommand("nSTATS\n");
        stats->setPlainText(stat.isEmpty() ? i18n("The ClamAV service is not reachable.") : friendlyStats(stat));

        const bool daemonRunning = daemon == QStringLiteral("active");
        const bool updatesRunning = freshclam == QStringLiteral("active") || timer == QStringLiteral("active");
        const bool databaseReady = databaseAvailable();
        const bool onAccessRunning = onAccess == QStringLiteral("active");
        const bool onAccessConfigured = onAccessPrevention->isChecked();
        const bool freshclamInitialized = QFile::exists(configDir + QStringLiteral("/freshclam.conf"));
        char quarantinePath[PATH_MAX];
        struct clamav_quarantine_entry *entries = nullptr;
        size_t quarantineItems = 0;
        size_t quarantineReview = 0;
        size_t quarantineSerious = 0;
        if (clamav_quarantine_path(quarantinePath) && clamav_quarantine_list(&entries, &quarantineItems))
        {
            for (size_t i = 0; i < quarantineItems; ++i) {
                if (quarantineLevel(entries[i].detection) >= 2)
                    ++quarantineReview;
                if (quarantineLevel(entries[i].detection) >= 3)
                    ++quarantineSerious;
            }
            clamav_quarantine_list_free(entries);
        }

        engineOverview->setText(daemonRunning ? i18n("Running") : i18n("Not running"));
        updatesOverview->setText(updatesRunning ? i18n("Updating automatically") : i18n("Schedule inactive"));
        databaseOverview->setText(databaseReady
            ? i18n("Installed\nLast updated %1", databaseUpdated())
            : i18n("Unavailable"));
        if (onAccessRunning)
            onAccessOverview->setText(i18n("Enabled and running"));
        else if (onAccessConfigured)
            onAccessOverview->setText(i18n("Enabled, not running"));
        else
            onAccessOverview->setText(i18n("Disabled (optional)"));
        if (quarantineReview > 0)
            quarantineOverview->setText(i18np("%1 item to review", "%1 items to review", static_cast<int>(quarantineReview)));
        else if (quarantineItems > 0)
            quarantineOverview->setText(i18n("Test signatures only"));
        else
            quarantineOverview->setText(i18n("No items to review"));

        const QColor green(80, 170, 100);
        const QColor yellow(220, 170, 30);
        const QColor red(210, 55, 65);
        setCardState(engineCard, daemonRunning ? green : red);
        setCardState(databaseCard, databaseReady ? green : red);
        setCardState(updatesCard, !freshclamInitialized ? red : (updatesRunning ? green : yellow));
        setCardState(onAccessCard, onAccessRunning ? green : (onAccessConfigured ? red : yellow));
        setCardState(quarantineCard, quarantineSerious > 0 ? red : (quarantineReview > 0 ? yellow : green));
        engineAction->setVisible(!daemonRunning);
        engineAction->setText(serviceEnabled(QStringLiteral("clamav-daemon.service")) == QStringLiteral("enabled")
            ? i18n("Start now") : i18n("Enable and start"));
        updatesAction->setVisible(!freshclamInitialized || !updatesRunning);
        updatesAction->setText(!freshclamInitialized ? i18n("Initialize FreshClam") : i18n("Enable updates"));
        onAccessAction->setVisible(!onAccessRunning);
        onAccessAction->setText(onAccessConfigured ? i18n("Start protection") : i18n("Enable and start"));
        quarantineAction->setVisible(quarantineReview > 0);

        healthAction->setVisible(true);
        if (!daemonRunning) {
            setHealthIcon(QStringLiteral("dialog-error"));
            healthTitle->setText(i18n("Attention needed"));
            healthDetails->setText(i18n("The ClamAV scanning service is not running. Enable and start it to scan files."));
            healthAction->setText(i18n("Start ClamAV"));
            healthActionType = 1;
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(210, 55, 65, 45); border: 1px solid rgba(210, 55, 65, 150); border-radius: 8px; }"));
        } else if (!databaseReady || !freshclamInitialized) {
            setHealthIcon(QStringLiteral("dialog-error"));
            healthTitle->setText(i18n("Database setup needed"));
            healthDetails->setText(!freshclamInitialized
                ? i18n("ClamAV is running, but FreshClam has not been initialized. Set up database updates before relying on current protection.")
                : i18n("ClamAV is running, but its virus database is unavailable. Initialize or update FreshClam."));
            healthAction->setText(i18n("Set up updates"));
            healthActionType = 2;
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(210, 55, 65, 45); border: 1px solid rgba(210, 55, 65, 150); border-radius: 8px; }"));
        } else if (onAccessConfigured && !onAccessRunning) {
            setHealthIcon(QStringLiteral("dialog-error"));
            healthTitle->setText(i18n("On-access protection needs attention"));
            healthDetails->setText(i18n("On-access prevention is enabled in ClamAV configuration, but its service is not running."));
            healthAction->setText(i18n("Start protection"));
            healthActionType = 3;
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(210, 55, 65, 45); border: 1px solid rgba(210, 55, 65, 150); border-radius: 8px; }"));
        } else if (quarantineReview > 0 || !updatesRunning) {
            setHealthIcon(QStringLiteral("dialog-warning"));
            healthTitle->setText(i18n("Protection is running"));
            if (quarantineReview > 0) {
                const QString reviewText = quarantineSerious > 0
                    ? i18n("Some quarantined detections may be serious.")
                    : i18n("Potentially unwanted items are quarantined.");
                healthDetails->setText(i18n("ClamAV is available. %1 On-access protection is %2.", reviewText,
                                            onAccessRunning ? i18n("enabled") : i18n("not enabled")));
                healthAction->setText(i18n("Review quarantine"));
                healthActionType = 4;
            } else if (!updatesRunning) {
                healthDetails->setText(i18n("ClamAV is available, but automatic virus database updates are not active."));
                healthAction->setText(i18n("Enable updates"));
                healthActionType = 2;
            } else {
                healthDetails->setText(i18n("ClamAV is available, but automatic virus database updates are not active."));
                healthAction->setText(i18n("Enable updates"));
                healthActionType = 2;
            }
            healthAction->setVisible(true);
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(220, 170, 30, 45); border: 1px solid rgba(220, 170, 30, 150); border-radius: 8px; }"));
        } else {
            setHealthIcon(QStringLiteral("emblem-ok"));
            healthTitle->setText(i18n("ClamAV is operating normally"));
            healthDetails->setText(i18n("The antivirus service is running, the virus database is available, and automatic updates are active."));
            healthAction->setVisible(false);
            healthActionType = 0;
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(80, 170, 100, 45); border: 1px solid rgba(80, 170, 100, 150); border-radius: 8px; }"));
        }
        updateAuditAvailability();
    }
};

K_PLUGIN_CLASS_WITH_JSON(ClamavKCM, "kcm_clamav.json")

#include "kcm_clamav.moc"
