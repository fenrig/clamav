#include <KLocalizedString>
#include <KCModule>
#include <KPluginFactory>

#include "quarantine.h"

#include <QCheckBox>
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
#include <QTabWidget>
#include <QTextStream>
#include <QRegularExpression>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const QString configDir = QStringLiteral(CLAMAV_CONF_DIR);
const QString dataDir = QStringLiteral(CLAMAV_DATA_DIR);
const QString helper = QStringLiteral(CLAMAV_LIBEXEC_DIR) + QStringLiteral("/clamav-kcm-helper");

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
    const QFileInfoList files = QDir(directory).entryInfoList(
        {QStringLiteral("main.*"), QStringLiteral("daily.*"), QStringLiteral("bytecode.*")},
        QDir::Files, QDir::Time);
    return files.isEmpty() ? QString() : QLocale().toString(files.first().lastModified(), QLocale::ShortFormat);
}

bool databaseAvailable()
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
    return !QDir(directory).entryInfoList(
        {QStringLiteral("main.*"), QStringLiteral("daily.*"), QStringLiteral("bytecode.*")},
        QDir::Files).isEmpty();
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
        subtitle->setStyleSheet(QStringLiteral("color: palette(mid);"));
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
        tabs->addTab(overviewPage, QIcon::fromTheme(QStringLiteral("view-dashboard")), i18n("Overview"));
        tabs->addTab(scanningPage, QIcon::fromTheme(QStringLiteral("security-high")), i18n("Scanning"));
        tabs->addTab(updatesPage, QIcon::fromTheme(QStringLiteral("system-software-update")), i18n("Updates"));
        root->addWidget(tabs, 1);

        healthBanner = new QFrame(widget());
        healthBanner->setObjectName(QStringLiteral("healthBanner"));
        auto *healthLayout = new QVBoxLayout(healthBanner);
        healthLayout->setContentsMargins(16, 12, 16, 12);
        healthTitle = new QLabel(healthBanner);
        healthTitle->setStyleSheet(QStringLiteral("font-size: 17px; font-weight: 600; color: palette(window-text);"));
        healthDetails = new QLabel(healthBanner);
        healthDetails->setWordWrap(true);
        healthDetails->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        healthLayout->addWidget(healthTitle);
        healthLayout->addWidget(healthDetails);
        overviewLayout->addWidget(healthBanner);

        auto *overview = new QGridLayout;
        overview->setHorizontalSpacing(10);
        overview->setVerticalSpacing(10);
        const auto addOverviewCard = [overview](const QString &title, int row, int column) {
            auto *card = new QFrame;
            card->setObjectName(QStringLiteral("overviewCard"));
            auto *cardLayout = new QVBoxLayout(card);
            cardLayout->setContentsMargins(14, 12, 14, 12);
            auto *heading = new QLabel(title, card);
            heading->setStyleSheet(QStringLiteral("font-weight: 600; color: palette(mid);"));
            auto *value = new QLabel(card);
            value->setWordWrap(true);
            value->setStyleSheet(QStringLiteral("font-size: 15px; font-weight: 600; color: palette(window-text);"));
            cardLayout->addWidget(heading);
            cardLayout->addWidget(value);
            overview->addWidget(card, row, column);
            return value;
        };
        engineOverview = addOverviewCard(i18n("Antivirus"), 0, 0);
        updatesOverview = addOverviewCard(i18n("Database updates"), 0, 1);
        databaseOverview = addOverviewCard(i18n("Virus database"), 0, 2);
        onAccessOverview = addOverviewCard(i18n("On-access protection"), 1, 0);
        quarantineOverview = addOverviewCard(i18n("Quarantine"), 1, 1);
        auto *overviewSpacer = new QWidget(widget());
        overviewSpacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        overview->addWidget(overviewSpacer, 1, 2);
        overviewLayout->addLayout(overview);

        auto *statusBox = new QGroupBox(i18n("Status"), widget());
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
        status->addRow(i18n("Clam daemon:"), clamdStatus);
        status->addRow(i18n("FreshClam:"), freshclamStatus);
        status->addRow(i18n("On-access scanner:"), onAccessStatus);
        status->addRow(i18n("Update timer:"), timerStatus);
        status->addRow(i18n("Database:"), databaseStatus);
        status->addRow(i18n("Scanner statistics:"), stats);
        overviewLayout->addWidget(statusBox);

        auto *actions = new QGroupBox(i18n("Quick actions"), widget());
        auto *actionLayout = new QGridLayout(actions);
        actionLayout->setHorizontalSpacing(8);
        actionLayout->setVerticalSpacing(8);
        addAction(actionLayout, i18n("Reload database"), "reload", "clamav-daemon.service");
        addAction(actionLayout, i18n("Restart daemon"), "restart", "clamav-daemon.service");
        addAction(actionLayout, i18n("Update database now"), "start", "clamav-freshclam-once.service");
        addAction(actionLayout, i18n("Start on-access scanner"), "start", "clamav-clamonacc.service");
        addAction(actionLayout, i18n("Enable ClamAV daemon"), "enable", "clamav-daemon.service");
        addAction(actionLayout, i18n("Disable ClamAV daemon"), "disable", "clamav-daemon.service");
        addAction(actionLayout, i18n("Enable on-access scanner"), "enable", "clamav-clamonacc.service");
        addAction(actionLayout, i18n("Disable on-access scanner"), "disable", "clamav-clamonacc.service");
        addAction(actionLayout, i18n("Enable daily updates"), "enable", "clamav-freshclam-once.timer");
        addAction(actionLayout, i18n("Disable daily updates"), "disable", "clamav-freshclam-once.timer");
        auto *quarantine = new QPushButton(i18n("Open quarantine"), actions);
        quarantine->setIcon(QIcon::fromTheme(QStringLiteral("folder-open")));
        connect(quarantine, &QPushButton::clicked, this, &ClamavKCM::openQuarantine);
        addButton(actionLayout, quarantine);
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
        settingsIntro->setStyleSheet(QStringLiteral("color: palette(mid);"));
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
        updatesIntro->setStyleSheet(QStringLiteral("color: palette(mid);"));
        updatesForm->addRow(updatesIntro);
        freshclamSchedule = new QLineEdit(updates);
        freshclamSchedule->setPlaceholderText(i18n("For example: daily or Mon *-*-* 03:00:00"));
        freshclamDelay = new QLineEdit(updates);
        freshclamDelay->setPlaceholderText(i18n("For example: 1h or 15min"));
        updatesForm->addRow(i18n("Update schedule:"), freshclamSchedule);
        updatesForm->addRow(i18n("Randomized delay:"), freshclamDelay);
        scanningLayout->addWidget(settings);
        scanningLayout->addStretch();
        updatesLayout->addWidget(updates);
        updatesLayout->addStretch();
        connect(lazyLoading, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(keepAlive, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        connect(heuristicAlerts, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(heuristicPrecedence, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(onAccessPrevention, &QCheckBox::toggled, this, &ClamavKCM::settingsChanged);
        connect(freshclamSchedule, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        connect(freshclamDelay, &QLineEdit::textChanged, this, &ClamavKCM::settingsChanged);
        configWatcher = new QFileSystemWatcher(this);
        if (QFile::exists(configFile()))
            configWatcher->addPath(configFile());
        connect(configWatcher, &QFileSystemWatcher::fileChanged, this, &ClamavKCM::configurationChanged);
        statusTimer = new QTimer(this);
        statusTimer->setInterval(30000);
        connect(statusTimer, &QTimer::timeout, this, &ClamavKCM::refreshStatus);
        statusTimer->start();
        refreshStatus();
        load();
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
        lazyLoading->setChecked(value(QStringLiteral("OnDemandDatabase")) == QStringLiteral("yes"));
        keepAlive->setText(value(QStringLiteral("DatabaseKeepAlive"), QStringLiteral("5m")));
        heuristicAlerts->setChecked(value(QStringLiteral("HeuristicAlerts"), QStringLiteral("yes")) != QStringLiteral("no"));
        heuristicPrecedence->setChecked(value(QStringLiteral("HeuristicScanPrecedence")) == QStringLiteral("yes"));
        onAccessPrevention->setChecked(value(QStringLiteral("OnAccessPrevention")) == QStringLiteral("yes"));
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
        setNeedsSave(true);
        pendingChanges = true;
        applyButton->setEnabled(true);
    }

private:
    QFrame *healthBanner;
    QLabel *healthTitle, *healthDetails;
    QLabel *engineOverview, *updatesOverview, *databaseOverview, *onAccessOverview, *quarantineOverview;
    QLabel *clamdStatus, *freshclamStatus, *onAccessStatus, *timerStatus, *databaseStatus;
    QPlainTextEdit *stats;
    QCheckBox *lazyLoading, *heuristicAlerts, *heuristicPrecedence, *onAccessPrevention;
    QLineEdit *keepAlive;
    QLineEdit *freshclamSchedule, *freshclamDelay;
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
    void openQuarantine()
    {
        if (!QProcess::startDetached(QStringLiteral("clamav-quarantine-gui")))
            QMessageBox::warning(widget(), i18n("ClamAV"),
                                 i18n("The quarantine manager could not be opened."));
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
        if (!pendingChanges)
            loadTimerSettings();
        clamdStatus->setText(serviceState(QStringLiteral("clamav-daemon.service")));
        freshclamStatus->setText(serviceState(QStringLiteral("clamav-freshclam.service")));
        onAccessStatus->setText(serviceState(QStringLiteral("clamav-clamonacc.service")));
        timerStatus->setText(serviceState(QStringLiteral("clamav-freshclam-once.timer")));
        const QString response = clamdCommand("nVERSION\n");
        databaseStatus->setText(databaseInfo() + (response.isEmpty() ? QString() : QStringLiteral("; ") + response.trimmed()));
        const QString stat = clamdCommand("nSTATS\n");
        stats->setPlainText(stat.isEmpty() ? i18n("Clamd is not reachable") : stat.trimmed());

        const QString daemon = clamdStatus->text();
        const QString freshclam = freshclamStatus->text();
        const QString timer = timerStatus->text();
        const QString onAccess = onAccessStatus->text();
        const bool daemonRunning = daemon == QStringLiteral("active");
        const bool updatesRunning = freshclam == QStringLiteral("active") || timer == QStringLiteral("active");
        const bool databaseReady = databaseAvailable();
        const bool onAccessRunning = onAccess == QStringLiteral("active");
        const bool onAccessConfigured = serviceEnabled(QStringLiteral("clamav-clamonacc.service")) == QStringLiteral("enabled");
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
            ? i18n("Available\nUpdated %1", databaseUpdated())
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

        if (!daemonRunning || !databaseReady) {
            healthTitle->setText(i18n("Attention needed"));
            healthDetails->setText(!daemonRunning
                ? i18n("The ClamAV scanning service is not running. Start it from Quick actions or check the service configuration.")
                : i18n("The virus database is unavailable. Update the database before relying on scans."));
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(210, 55, 65, 45); border: 1px solid rgba(210, 55, 65, 150); border-radius: 8px; }"));
        } else if (quarantineReview > 0 || !onAccessRunning) {
            healthTitle->setText(i18n("Protection is running"));
            if (quarantineReview > 0) {
                const QString reviewText = quarantineSerious > 0
                    ? i18n("Some quarantined detections may be serious.")
                    : i18n("Potentially unwanted items are quarantined.");
                healthDetails->setText(i18n("ClamAV is available. %1 On-access protection is %2.", reviewText,
                                            onAccessRunning ? i18n("enabled") : i18n("not enabled")));
            } else {
                healthDetails->setText(i18n("ClamAV is available. On-access protection is disabled, which is optional but provides less automatic protection."));
            }
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(220, 170, 30, 45); border: 1px solid rgba(220, 170, 30, 150); border-radius: 8px; }"));
        } else if (!updatesRunning) {
            healthTitle->setText(i18n("Protection is running"));
            healthDetails->setText(i18n("Scanning is available, but automatic virus database updates are not active."));
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(220, 170, 30, 45); border: 1px solid rgba(220, 170, 30, 150); border-radius: 8px; }"));
        } else {
            healthTitle->setText(i18n("ClamAV is operating normally"));
            healthDetails->setText(i18n("The antivirus service is running, the virus database is available, and automatic updates are active."));
            healthBanner->setStyleSheet(QStringLiteral("QFrame#healthBanner { background: rgba(80, 170, 100, 45); border: 1px solid rgba(80, 170, 100, 150); border-radius: 8px; }"));
        }
    }
};

K_PLUGIN_CLASS_WITH_JSON(ClamavKCM, "kcm_clamav.json")

#include "kcm_clamav.moc"
