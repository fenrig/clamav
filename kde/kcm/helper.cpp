/* Narrow, polkit-authorized operations used by the Plasma KCM. */
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTextStream>
#include <QProcess>
#include <QDateTime>
#include <QDir>

#include <unistd.h>
#include <utility>

#ifndef CLAMAV_CONF_DIR
#define CLAMAV_CONF_DIR "/etc/clamav"
#endif

namespace {
const QString clamdConfig = QStringLiteral(CLAMAV_CONF_DIR) + QStringLiteral("/clamd.conf");
const QString freshclamTimerOverride = QStringLiteral("/etc/systemd/system/clamav-freshclam-once.timer.d/override.conf");

bool safeValue(const QString &value)
{
    return !value.contains('\n') && !value.contains('\r') && !value.contains('\0');
}

bool validTimerValue(const QString &key, const QString &value)
{
    if (key != QStringLiteral("OnCalendar") && key != QStringLiteral("RandomizedDelaySec"))
        return false;
    if (!safeValue(value) || value.isEmpty() || value.size() > 256)
        return false;
    if (value.contains(QLatin1Char('[')) || value.contains(QLatin1Char(']')))
        return false;
    return true;
}

bool writeTimerOverride(const QString &schedule, const QString &randomizedDelay)
{
    if (!validTimerValue(QStringLiteral("OnCalendar"), schedule)
        || !validTimerValue(QStringLiteral("RandomizedDelaySec"), randomizedDelay))
        return false;
    const QFileInfo info(freshclamTimerOverride);
    if (!QDir().mkpath(info.absolutePath()))
        return false;
    QSaveFile output(freshclamTimerOverride);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;
    QTextStream stream(&output);
    stream << "[Timer]\n"
           << "OnCalendar=\n"
           << "OnCalendar=" << schedule << '\n'
           << "RandomizedDelaySec=" << randomizedDelay << '\n';
    return output.commit();
}

bool allowedScalar(const QString &key, const QString &value)
{
    static const QStringList keys = {
        QStringLiteral("OnDemandDatabase"), QStringLiteral("DatabaseKeepAlive"),
        QStringLiteral("HeuristicAlerts"), QStringLiteral("HeuristicScanPrecedence"),
        QStringLiteral("AlertBrokenExecutables"), QStringLiteral("AlertBrokenMedia"),
        QStringLiteral("AlertEncrypted"), QStringLiteral("AlertOLE2Macros"),
        QStringLiteral("AlertPhishingSSLMismatch"), QStringLiteral("OnAccessPrevention"),
        QStringLiteral("OnAccessExtraScanning"), QStringLiteral("OnAccessMaxThreads"),
        QStringLiteral("OnAccessMaxFileSize")};
    if (!keys.contains(key) || !safeValue(value))
        return false;
    if (key == QStringLiteral("DatabaseKeepAlive"))
        return value.contains(QRegularExpression(QStringLiteral("^[0-9]+[smh]$")));
    if (key.endsWith(QStringLiteral("Threads")))
        return value.contains(QRegularExpression(QStringLiteral("^[1-9][0-9]*$")));
    if (key.endsWith(QStringLiteral("FileSize")))
        return value.contains(QRegularExpression(QStringLiteral("^[0-9]+[KMGkmg]?$")));
    if (key == QStringLiteral("OnDemandDatabase") || key.startsWith(QStringLiteral("Heuristic"))
        || key.startsWith(QStringLiteral("Alert")) || key.startsWith(QStringLiteral("OnAccess")))
        return value == QStringLiteral("yes") || value == QStringLiteral("no");
    return true;
}

bool writeScalar(const QString &key, const QString &value)
{
    if (!allowedScalar(key, value))
        return false;
    QFile input(clamdConfig);
    QStringList lines;
    if (input.exists() && input.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&input);
        while (!stream.atEnd())
            lines << stream.readLine();
        input.close();
    }
    const QRegularExpression active(QStringLiteral("^\\s*") + QRegularExpression::escape(key) + QStringLiteral("\\s+.*$"));
    bool replaced = false;
    for (QString &line : lines) {
        if (active.match(line).hasMatch()) {
            line = key + QLatin1Char(' ') + value;
            replaced = true;
        }
    }
    if (!replaced)
        lines << key + QLatin1Char(' ') + value;

    if (QFile::exists(clamdConfig))
        QFile::copy(clamdConfig, clamdConfig + QStringLiteral(".bak.")
                    + QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMddhhmmss")));
    QSaveFile output(clamdConfig);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;
    QTextStream stream(&output);
    stream << lines.join(QLatin1Char('\n')) << QLatin1Char('\n');
    return output.commit();
}

bool writePaths(const QString &key, const QStringList &values)
{
    if (key != QStringLiteral("OnAccessIncludePath") && key != QStringLiteral("OnAccessExcludePath")
        && key != QStringLiteral("OnAccessMountPath") && key != QStringLiteral("OnAccessDownloadPath"))
        return false;
    for (const QString &value : values) {
        if (!safeValue(value) || !QDir::isAbsolutePath(value) || value.contains(QRegularExpression(QStringLiteral("[\\t ]"))))
            return false;
    }
    QFile input(clamdConfig);
    QStringList lines;
    if (input.exists() && input.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&input);
        while (!stream.atEnd())
            lines << stream.readLine();
        input.close();
    }
    const QRegularExpression active(QStringLiteral("^\\s*") + QRegularExpression::escape(key) + QStringLiteral("\\s+.*$"));
    QStringList kept;
    for (const QString &line : std::as_const(lines))
        if (!active.match(line).hasMatch())
            kept << line;
    for (const QString &value : values)
        kept << key + QLatin1Char(' ') + value;
    if (QFile::exists(clamdConfig))
        QFile::copy(clamdConfig, clamdConfig + QStringLiteral(".bak.")
                    + QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMddhhmmss")));
    QSaveFile output(clamdConfig);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;
    QTextStream stream(&output);
    stream << kept.join(QLatin1Char('\n')) << QLatin1Char('\n');
    return output.commit();
}

int systemctl(const QStringList &arguments)
{
    if (::geteuid() != 0 || arguments.isEmpty())
        return 1;
    const QString executable = QFile::exists(QStringLiteral("/usr/bin/systemctl"))
        ? QStringLiteral("/usr/bin/systemctl") : QStringLiteral("/bin/systemctl");
    QProcess process;
    process.start(executable, arguments);
    if (!process.waitForFinished(30000))
        return 1;
    return process.exitCode();
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments();
    if (args.size() < 2 || ::geteuid() != 0)
        return 2;
    if (args[1] == QStringLiteral("write-clamd") && args.size() == 4)
        return writeScalar(args[2], args[3]) ? 0 : 1;
    if (args[1] == QStringLiteral("write-paths") && args.size() >= 3)
        return writePaths(args[2], args.mid(3)) ? 0 : 1;
    if (args[1] == QStringLiteral("timer-set") && args.size() == 4) {
        if (!writeTimerOverride(args[2], args[3]))
            return 1;
        return systemctl({QStringLiteral("daemon-reload")});
    }
    if (args[1] == QStringLiteral("service") && args.size() == 4) {
        const QString action = args[2];
        const QString unit = args[3];
        static const QStringList units = {QStringLiteral("clamav-daemon.service"),
            QStringLiteral("clamav-freshclam.service"), QStringLiteral("clamav-freshclam-once.service"),
            QStringLiteral("clamav-freshclam-once.timer"), QStringLiteral("clamav-clamonacc.service")};
        static const QStringList actions = {QStringLiteral("start"), QStringLiteral("stop"),
            QStringLiteral("restart"), QStringLiteral("reload"), QStringLiteral("enable"),
            QStringLiteral("disable")};
        if (!units.contains(unit) || !actions.contains(action))
            return 1;
        return systemctl({action, unit});
    }
    return 2;
}
