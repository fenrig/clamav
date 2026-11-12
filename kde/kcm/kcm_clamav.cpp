#include <KLocalizedString>
#include <KCModule>
#include <KPluginFactory>

#include <QCheckBox>
#include <QFile>
#include <QFileSystemWatcher>
#include <QFileInfo>
#include <QDir>
#include <QHash>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QGroupBox>
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
        auto *statusBox = new QGroupBox(i18n("Status"), widget());
        auto *status = new QFormLayout(statusBox);
        clamdStatus = new QLabel;
        freshclamStatus = new QLabel;
        onAccessStatus = new QLabel;
        timerStatus = new QLabel;
        databaseStatus = new QLabel;
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
        root->addWidget(statusBox);

        auto *actions = new QGroupBox(i18n("Actions"), widget());
        auto *actionLayout = new QHBoxLayout(actions);
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
        auto *refresh = new QPushButton(i18n("Refresh"), actions);
        connect(refresh, &QPushButton::clicked, this, &ClamavKCM::refreshStatus);
        actionLayout->addWidget(refresh);
        applyButton = new QPushButton(i18n("Apply configuration"), actions);
        applyButton->setEnabled(false);
        connect(applyButton, &QPushButton::clicked, this, &ClamavKCM::save);
        actionLayout->addWidget(applyButton);
        root->addWidget(actions);

        auto *settings = new QGroupBox(i18n("Scanner configuration"), widget());
        auto *form = new QFormLayout(settings);
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
        freshclamSchedule = new QLineEdit(settings);
        freshclamSchedule->setPlaceholderText(i18n("For example: daily or Mon *-*-* 03:00:00"));
        freshclamDelay = new QLineEdit(settings);
        freshclamDelay->setPlaceholderText(i18n("For example: 1h or 15min"));
        form->addRow(i18n("FreshClam schedule:"), freshclamSchedule);
        form->addRow(i18n("FreshClam randomized delay:"), freshclamDelay);
        root->addWidget(settings);
        root->addStretch();
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
    void addAction(QHBoxLayout *layout, const QString &label, const QString &action, const QString &unit)
    {
        auto *button = new QPushButton(label, widget());
        connect(button, &QPushButton::clicked, this, [this, action, unit] { runHelper({QStringLiteral("service"), action, unit}); refreshStatus(); });
        layout->addWidget(button);
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
    }
};

K_PLUGIN_CLASS_WITH_JSON(ClamavKCM, "kcm_clamav.json")

#include "kcm_clamav.moc"
