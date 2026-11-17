/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#include "quarantine.h"

#include <QApplication>
#include <QCheckBox>
#include <QColor>
#include <QBrush>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFormLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QFontDatabase>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QLockFile>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPushButton>
#include <QProgressBar>
#include <QRegularExpression>
#include <QFrame>
#include <QSplitter>
#include <QSignalBlocker>
#include <QTextEdit>
#include <QTabWidget>
#include <QTimer>
#include <QUrl>
#include <QStandardPaths>
#include <QLocale>
#include <QTranslator>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <memory>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

static QString localDescription(const QString &detection)
{
    const QString name = detection.section('\n', 0, 0).section(QStringLiteral(": "), -1).trimmed();
    if (name.startsWith(QStringLiteral("Eicar-Signature"), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("Eicar-Test-Signature"), Qt::CaseInsensitive))
        return QObject::tr("This is the standard harmless EICAR antivirus test file, not a real infection. It can be safely deleted; it is only used to verify that antivirus protection is working.");
    if (name.startsWith(QStringLiteral("PUA."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("PUP."), Qt::CaseInsensitive))
        return QObject::tr("ClamAV classified this as a potentially unwanted application. It may be unwanted or unsafe, but is not necessarily malware.");
    if (name.startsWith(QStringLiteral("Phishing."), Qt::CaseInsensitive))
        return QObject::tr("ClamAV classified this as phishing content intended to trick users into disclosing information or opening unsafe content.");
    if (name.startsWith(QStringLiteral("Heuristics."), Qt::CaseInsensitive))
        return QObject::tr("This is a heuristic detection. ClamAV found suspicious characteristics, but the signature name may not identify a specific malware family.");
    if (name.contains(QStringLiteral("Trojan"), Qt::CaseInsensitive))
        return QObject::tr("The detection name identifies this as Trojan-like malware. Keep it quarantined unless you can verify it is a false positive.");
    if (name.contains(QStringLiteral("Virus"), Qt::CaseInsensitive)
            || name.contains(QStringLiteral("Worm"), Qt::CaseInsensitive))
        return QObject::tr("The detection name identifies this as a virus or worm signature associated with malicious code.");
    return QObject::tr("ClamAV reported a signature match. Use the web-search or VirusTotal buttons for more context; these results are informational and may be incomplete.");
}

static void appendMetadataLines(const QJsonObject &object, QStringList &lines,
                                const QString &indent = QString())
{
    for (const QString &key : object.keys()) {
        QString label = key;
        label.replace(QLatin1Char('_'), QLatin1Char(' '));
        if (!label.isEmpty())
            label[0] = label.at(0).toUpper();
        const QJsonValue value = object.value(key);
        if (value.isObject()) {
            lines << QStringLiteral("%1%2:").arg(indent, label);
            appendMetadataLines(value.toObject(), lines, indent + QStringLiteral("  "));
        } else if (value.isArray()) {
            QStringList values;
            for (const QJsonValue &item : value.toArray())
                values << (item.isString() ? item.toString() : QStringLiteral("[value]"));
            lines << QStringLiteral("%1%2: %3").arg(indent, label, values.join(QStringLiteral(", ")));
        } else if (value.isString()) {
            lines << QStringLiteral("%1%2: %3").arg(indent, label, value.toString());
        } else if (value.isBool()) {
            lines << QStringLiteral("%1%2: %3").arg(indent, label, value.toBool() ? QObject::tr("Yes") : QObject::tr("No"));
        } else if (value.isNull()) {
            lines << QStringLiteral("%1%2: %3").arg(indent, label, QObject::tr("Not set"));
        } else {
            lines << QStringLiteral("%1%2: %3").arg(indent, label, QString::number(value.toDouble()));
        }
    }
}

static QString formattedMetadata(const QString &serialized)
{
    if (serialized.trimmed().isEmpty() || serialized.trimmed() == QStringLiteral("{}"))
        return QObject::tr("No metadata recorded.");
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(serialized.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        return QObject::tr("Metadata unavailable.");
    QStringList lines;
    appendMetadataLines(document.object(), lines);
    return lines.isEmpty() ? QObject::tr("No metadata recorded.") : lines.join(QLatin1Char('\n'));
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
        if (record.contains(QStringLiteral("id")))
            lines << QStringLiteral("  %1: %2").arg(QObject::tr("ID"), record.value(QStringLiteral("id")).toString());
        if (record.contains(QStringLiteral("detail")))
            lines << QStringLiteral("  %1: %2").arg(QObject::tr("Details"), record.value(QStringLiteral("detail")).toString());
        lines << QString();
    }
    return lines.isEmpty() ? QObject::tr("No readable log entries yet.") : lines.join(QLatin1Char('\n'));
}

static int threatLevel(const QString &detection)
{
    const QString name = detection.section('\n', 0, 0).section(QStringLiteral(": "), -1).trimmed();
    if (name.compare(QStringLiteral("Manually quarantined"), Qt::CaseInsensitive) == 0)
        return 0;
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

static QString threatLabel(const QString &detection)
{
    switch (threatLevel(detection)) {
    case 0:
        return QObject::tr("Unknown") + QStringLiteral(" (?)");
    case 1:
        return QObject::tr("Test signature — harmless");
    case 2:
        return QObject::tr("Potentially unwanted");
    case 3:
        return QObject::tr("Suspicious content");
    default:
        return QObject::tr("Malware detection");
    }
}

static QColor threatTint(const QString &detection)
{
    const QString name = detection.section('\n', 0, 0).section(QStringLiteral(": "), -1).trimmed();
    if (name.compare(QStringLiteral("Manually quarantined"), Qt::CaseInsensitive) == 0)
        return QColor(61, 174, 233, 55);
    if (name.startsWith(QStringLiteral("Eicar"), Qt::CaseInsensitive))
        return QColor(80, 170, 100, 45);
    if (name.startsWith(QStringLiteral("PUA."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("PUP."), Qt::CaseInsensitive))
        return QColor(220, 170, 30, 55);
    if (name.startsWith(QStringLiteral("Phishing."), Qt::CaseInsensitive)
            || name.startsWith(QStringLiteral("Heuristics."), Qt::CaseInsensitive))
        return QColor(235, 125, 30, 55);
    return QColor(210, 55, 65, 50);
}

class DeselectableTableWidget final : public QTableWidget
{
public:
    using QTableWidget::QTableWidget;

protected:
    void mousePressEvent(QMouseEvent *event) override
    {
        const QModelIndex index = indexAt(event->position().toPoint());
        if (event->modifiers() == Qt::NoModifier
                && (!index.isValid() || selectionModel()->isSelected(index))) {
            clearSelection();
            setCurrentItem(nullptr);
            event->accept();
            return;
        }
        QTableWidget::mousePressEvent(event);
    }
};

class QuarantineWindow final : public QMainWindow
{
public:
    QuarantineWindow()
    {
        auto *central = new QWidget(this);
        quarantinePage_ = central;
        auto *layout = new QVBoxLayout(central);
        auto *toolbar = new QHBoxLayout;
        auto *listToolbar = new QHBoxLayout;
        pathLabel = new QLabel(this);
        table = new DeselectableTableWidget(this);
        searchBox = new QLineEdit(this);
        searchBox->setPlaceholderText(tr("Search detections, filenames, or components…"));
        statusHeader = new QFrame(this);
        statusHeader->setObjectName(QStringLiteral("statusHeader"));
        statusHeaderQuarantineIcon = new QLabel(statusHeader);
        statusHeaderQuarantineIcon->setFixedSize(32, 32);
        statusHeaderQuarantineIcon->setAlignment(Qt::AlignCenter);
        const QStringList quarantineIconNames = {
            QStringLiteral("clamav-quarantine"), QStringLiteral("clamav"),
            QStringLiteral("folder-locked"), QStringLiteral("security-high"), QStringLiteral("folder")};
        for (const QString &iconName : quarantineIconNames) {
            const QIcon icon = QIcon::fromTheme(iconName);
            if (!icon.isNull()) {
                statusHeaderQuarantineIcon->setPixmap(icon.pixmap(28, 28));
                break;
            }
        }
        if (statusHeaderQuarantineIcon->pixmap(Qt::ReturnByValue).isNull())
            statusHeaderQuarantineIcon->setText(QStringLiteral("🔒"));
        statusHeaderIcon = new QLabel(statusHeader);
        statusHeaderIcon->setFixedSize(32, 32);
        statusHeaderIcon->setAlignment(Qt::AlignCenter);
        statusHeaderTitle = new QLabel(statusHeader);
        statusHeaderDetails = new QLabel(statusHeader);
        componentLabel = new QLabel(tr("Select an item"), this);
        originalLabel = new QLabel(this);
        sourceLabel = new QLabel(this);
        originLabel = new QLabel(this);
        metadataLabel = new QLabel(this);
        hashLabel = new QLabel(this);
        createdLabel = new QLabel(this);
        descriptionLabel = new QLabel(this);
        severityLabel = new QLabel(this);
        severityMeter = new QProgressBar(this);
        details = new QTextEdit(this);
        refreshButton = new QPushButton(tr("Refresh"), this);
        restoreButton = new QPushButton(tr("Restore…"), this);
        deleteButton = new QPushButton(tr("Delete permanently"), this);
        deleteAllButton = new QPushButton(tr("Delete all permanently"), this);
        lookupButton = new QPushButton(tr("Look up detection"), this);
        virusTotalButton = new QPushButton(tr("Open VirusTotal"), this);
        refreshButton->setIcon(QIcon::fromTheme(QStringLiteral("view-refresh")));
        restoreButton->setIcon(QIcon::fromTheme(QStringLiteral("document-revert")));
        deleteButton->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete")));
        deleteAllButton->setIcon(QIcon::fromTheme(QStringLiteral("trash-empty")));
        lookupButton->setIcon(QIcon::fromTheme(QStringLiteral("internet-web-browser")));
        virusTotalButton->setIcon(QIcon::fromTheme(QStringLiteral("internet-services")));

        table->setColumnCount(3);
        table->setHorizontalHeaderLabels({tr("Original filename"), tr("Detected by"), tr("Date")});
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->verticalHeader()->setVisible(false);
        table->verticalHeader()->setDefaultSectionSize(38);
        auto listFont = table->font();
        listFont.setPointSize(listFont.pointSize() + 1);
        table->setFont(listFont);
        auto headerFont = table->horizontalHeader()->font();
        headerFont.setBold(true);
        table->horizontalHeader()->setFont(headerFont);
        restoreButton->setEnabled(false);
        deleteButton->setEnabled(false);
        deleteAllButton->setEnabled(false);
        lookupButton->setEnabled(false);
        virusTotalButton->setEnabled(false);
        details->setReadOnly(true);
        details->setMinimumHeight(140);
        details->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        sourceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        originLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        originLabel->setWordWrap(true);
        metadataLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        metadataLabel->setWordWrap(true);
        hashLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        descriptionLabel->setWordWrap(true);
        severityMeter->setRange(0, 4);
        severityMeter->setTextVisible(false);
        severityMeter->setFixedHeight(8);
        severityMeter->setAccessibleName(tr("Threat level"));

        auto *detailWidget = new QWidget(this);
        auto *detailLayout = new QVBoxLayout(detailWidget);
        emptyState = new QLabel(detailWidget);
        emptyState->setObjectName(QStringLiteral("emptyState"));
        emptyState->setTextFormat(Qt::RichText);
        emptyState->setTextInteractionFlags(Qt::TextBrowserInteraction);
        emptyState->setOpenExternalLinks(true);
        emptyState->setWordWrap(true);
        emptyState->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
        emptyState->setText(tr("<h2>Nothing selected</h2>"
                               "<p>Select a quarantined item to view its detection details, source, and ClamAV report.</p>"
                               "<p><b>Restore</b> only when you trust the file and understand the detection. "
                               "<b>Delete permanently</b> removes the isolated file.</p>"
                               "<p><a href=\"https://docs.clamav.net/\">Open ClamAV documentation</a></p>"));
        emptyState->setAlignment(Qt::AlignCenter);
        emptyState->setStyleSheet(QStringLiteral(
            "QLabel#emptyState { font-size: 16px; color: palette(window-text); padding: 32px; }"
            "QLabel#emptyState a { color: palette(link); }"));
        detailContent = new QWidget(detailWidget);
        auto *contentLayout = new QVBoxLayout(detailContent);
        contentLayout->setContentsMargins(0, 0, 0, 0);
        auto *detailTitle = new QLabel(tr("Detection details"), detailContent);
        detailTitle->setStyleSheet(QStringLiteral("font-size: 20px; font-weight: 600; padding-bottom: 4px;"));
        auto *form = new QFormLayout;
        form->addRow(tr("Component:"), componentLabel);
        form->addRow(tr("Original name:"), originalLabel);
        form->addRow(tr("Source path:"), sourceLabel);
        form->addRow(tr("Origin:"), originLabel);
        form->addRow(tr("Metadata:"), metadataLabel);
        form->addRow(tr("SHA-256:"), hashLabel);
        form->addRow(tr("Created:"), createdLabel);
        contentLayout->addWidget(detailTitle);
        contentLayout->addLayout(form);
        auto *summaryCard = new QFrame(detailContent);
        summaryCard->setObjectName(QStringLiteral("summaryCard"));
        auto *summaryLayout = new QVBoxLayout(summaryCard);
        auto *summaryTitle = new QLabel(tr("What this means"), summaryCard);
        summaryTitle->setStyleSheet(QStringLiteral("font-weight: 600;"));
        summaryLayout->addWidget(summaryTitle);
        summaryLayout->addWidget(severityLabel);
        summaryLayout->addWidget(severityMeter);
        summaryLayout->addWidget(descriptionLabel);

        auto *reportCard = new QFrame(detailContent);
        reportCard->setObjectName(QStringLiteral("reportCard"));
        auto *reportLayout = new QVBoxLayout(reportCard);
        auto *reportTitle = new QLabel(tr("Technical ClamAV report"), reportCard);
        reportTitle->setStyleSheet(QStringLiteral("font-weight: 600;"));
        reportLayout->addWidget(reportTitle);
        reportLayout->addWidget(details, 1);

        contentLayout->addWidget(summaryCard);
        contentLayout->addWidget(reportCard, 1);
        detailLayout->addWidget(emptyState, 1);
        detailLayout->addWidget(detailContent, 1);

        auto *splitter = new QSplitter(Qt::Horizontal, central);
        auto *listWidget = new QWidget(splitter);
        auto *listLayout = new QVBoxLayout(listWidget);
        listLayout->setContentsMargins(0, 0, 0, 0);
        auto *listTitle = new QLabel(tr("Quarantined detections"), listWidget);
        listTitle->setStyleSheet(QStringLiteral("color: palette(window-text); font-weight: 600;"));
        listLayout->addWidget(listTitle);
        listToolbar->addWidget(searchBox);
        auto *filterLabel = new QLabel(tr("Filter"), listWidget);
        filterLabel->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        listToolbar->addWidget(filterLabel);
        listLayout->addLayout(listToolbar);
        listLayout->addWidget(table);
        splitter->addWidget(listWidget);
        splitter->addWidget(detailWidget);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        splitter->setSizes({600, 400});

        auto *statusLayout = new QHBoxLayout(statusHeader);
        statusLayout->setContentsMargins(16, 12, 16, 12);
        statusLayout->addWidget(statusHeaderQuarantineIcon);
        statusLayout->addWidget(statusHeaderIcon);
        auto *statusText = new QVBoxLayout;
        statusHeaderTitle->setStyleSheet(QStringLiteral("font-size: 16px; font-weight: 600; color: palette(window-text); border: none; background: transparent;"));
        statusHeaderDetails->setWordWrap(true);
        statusHeaderDetails->setStyleSheet(QStringLiteral("color: palette(window-text); border: none; background: transparent;"));
        statusText->addWidget(statusHeaderTitle);
        statusText->addWidget(statusHeaderDetails);
        statusLayout->addLayout(statusText, 1);
        addFromEmptyButton = new QPushButton(tr("Add file"), statusHeader);
        addFromEmptyButton->setIcon(QIcon::fromTheme(QStringLiteral("document-open")));
        addFromEmptyButton->setVisible(false);
        statusLayout->addWidget(addFromEmptyButton);
        pathLabel->setStyleSheet(QStringLiteral("color: palette(window-text);"));
        layout->addWidget(splitter, 1);
        toolbar->addWidget(refreshButton);
        toolbar->addStretch();
        toolbar->addWidget(restoreButton);
        toolbar->addWidget(deleteButton);
        toolbar->addWidget(deleteAllButton);
        toolbar->addWidget(lookupButton);
        toolbar->addWidget(virusTotalButton);
        layout->addLayout(toolbar);
        auto *tabs = new QTabWidget(this);
        tabs_ = tabs;
        tabs->setTabPosition(QTabWidget::West);
        tabs->addTab(central, tr("Quarantine"));

        auto *addPage = new QWidget(tabs);
        auto *addLayout = new QVBoxLayout(addPage);
        addLayout->setContentsMargins(18, 18, 18, 18);
        auto *addHeader = new QHBoxLayout;
        auto *addTitle = new QLabel(tr("Add files to quarantine"), addPage);
        addTitle->setStyleSheet(QStringLiteral("font-size: 20px; font-weight: 600;"));
        addHeader->addWidget(addTitle);
        addHeader->addStretch();
        viewQuarantineButton = new QPushButton(tr("View quarantine"), addPage);
        viewQuarantineButton->setIcon(QIcon::fromTheme(QStringLiteral("view-list-details"),
                                                        QIcon::fromTheme(QStringLiteral("folder-open"))));
        viewQuarantineButton->setVisible(false);
        addHeader->addWidget(viewQuarantineButton);
        addLayout->addLayout(addHeader);
        auto *addInfoCard = new QFrame(addPage);
        addInfoCard->setObjectName(QStringLiteral("manualInfoCard"));
        auto *addInfoLayout = new QVBoxLayout(addInfoCard);
        auto *addInfoTitle = new QLabel(tr("Safe manual quarantine"), addInfoCard);
        addInfoTitle->setStyleSheet(QStringLiteral("font-weight: 600;"));
        addInfoLayout->addWidget(addInfoTitle);
        auto *addDescription = new QLabel(
            tr("Files are hashed, deduplicated, and copied into quarantine. Nothing is removed until you explicitly allow it."), addInfoCard);
        addDescription->setWordWrap(true);
        addDescription->setStyleSheet(QStringLiteral("color: palette(mid);"));
        addInfoLayout->addWidget(addDescription);
        addLayout->addWidget(addInfoCard);
        auto *filesHeader = new QHBoxLayout;
        auto *filesTitle = new QLabel(tr("Files to quarantine"), addPage);
        filesTitle->setStyleSheet(QStringLiteral("font-weight: 600;"));
        filesHeader->addWidget(filesTitle);
        filesHeader->addStretch();
        manualSummaryLabel = new QLabel(tr("No files selected"), addPage);
        manualSummaryLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));
        filesHeader->addWidget(manualSummaryLabel);
        addLayout->addLayout(filesHeader);
        manualFiles = new QListWidget(addPage);
        manualFiles->setSelectionMode(QAbstractItemView::ExtendedSelection);
        manualFiles->setAlternatingRowColors(true);
        manualFiles->setStyleSheet(QStringLiteral("QListWidget { border: 1px solid palette(mid); border-radius: 8px; padding: 4px; }"));
        manualEmptyLabel = new QLabel(tr("No files selected yet. Use “Add files…” to begin."), addPage);
        manualEmptyLabel->setAlignment(Qt::AlignCenter);
        manualEmptyLabel->setStyleSheet(QStringLiteral("color: palette(mid); padding: 24px;"));
        addLayout->addWidget(manualEmptyLabel);
        addLayout->addWidget(manualFiles, 1);
        auto *addButtons = new QHBoxLayout;
        manualChooseButton = new QPushButton(tr("Add files…"), addPage);
        manualRemoveButton = new QPushButton(tr("Remove selected"), addPage);
        manualQuarantineButton = new QPushButton(tr("Quarantine selected files"), addPage);
        manualChooseButton->setIcon(QIcon::fromTheme(QStringLiteral("document-open")));
        manualRemoveButton->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete")));
        manualQuarantineButton->setIcon(QIcon::fromTheme(QStringLiteral("security-high")));
        addButtons->addWidget(manualChooseButton);
        addButtons->addWidget(manualRemoveButton);
        addButtons->addStretch();
        addButtons->addWidget(manualQuarantineButton);
        addLayout->addLayout(addButtons);
        manualRemoveOriginals = new QCheckBox(tr("Remove original files after successful quarantine"), addPage);
        manualRemoveOriginals->setToolTip(tr("Leave this disabled to keep the original files in place."));
        addLayout->addWidget(manualRemoveOriginals);
        tabs->addTab(addPage, tr("Add files"));
        auto *logPage = new QWidget(tabs);
        auto *logLayout = new QVBoxLayout(logPage);
        auto *logHeader = new QHBoxLayout;
        auto *logTitle = new QLabel(tr("Quarantine log"), logPage);
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
        tabs->addTab(logPage, tr("Log"));
        logPath_ = auditLogPath(QStringLiteral("quarantine.log"));
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
            setQuarantineMonitoring(tabs_->currentWidget() == quarantinePage_);
        });
        quarantineWatcher_ = new QFileSystemWatcher(this);
        connect(quarantineWatcher_, &QFileSystemWatcher::directoryChanged, this, [this] {
            if (tabs_ && tabs_->currentWidget() == quarantinePage_)
                refreshInternal(false);
            setQuarantineWatchPath();
        });
        quarantineRefreshTimer_.setInterval(5000);
        connect(&quarantineRefreshTimer_, &QTimer::timeout, this, [this] {
            if (tabs_ && tabs_->currentWidget() == quarantinePage_)
                refreshInternal(false);
        });
        connect(manualChooseButton, &QPushButton::clicked, this, &QuarantineWindow::chooseManualFiles);
        connect(manualRemoveButton, &QPushButton::clicked, this, [this] {
            qDeleteAll(manualFiles->selectedItems());
            updateManualFileUi();
        });
        connect(manualFiles, &QListWidget::itemSelectionChanged, this, [this] {
            manualRemoveButton->setEnabled(!manualFiles->selectedItems().isEmpty());
        });
        connect(manualQuarantineButton, &QPushButton::clicked, this, &QuarantineWindow::quarantineManualFiles);
        connect(addFromEmptyButton, &QPushButton::clicked, this, [this] {
            tabs_->setCurrentIndex(1);
            chooseManualFiles();
        });
        connect(viewQuarantineButton, &QPushButton::clicked, this, [this] {
            tabs_->setCurrentIndex(0);
        });
        manualRemoveButton->setEnabled(false);
        manualQuarantineButton->setEnabled(false);
        updateManualFileUi();
        auto *window = new QWidget(this);
        auto *windowLayout = new QVBoxLayout(window);
        windowLayout->addWidget(statusHeader);
        windowLayout->addWidget(pathLabel);
        windowLayout->addWidget(tabs, 1);
        setCentralWidget(window);
        setWindowTitle(tr("ClamAV Quarantine"));
        resize(1100, 700);
        setStyleSheet(QStringLiteral(
            "QFrame#summaryCard { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#reportCard { background: palette(base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#manualInfoCard { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#summaryCard QLabel, QFrame#reportCard QLabel { border: none; }"
            "QFrame#manualInfoCard QLabel { border: none; background: transparent; }"
            "QTextEdit { border: none; background: transparent; }"));

        connect(refreshButton, &QPushButton::clicked, this, &QuarantineWindow::refresh);
        connect(restoreButton, &QPushButton::clicked, this, &QuarantineWindow::restore);
        connect(deleteButton, &QPushButton::clicked, this, &QuarantineWindow::remove);
        connect(deleteAllButton, &QPushButton::clicked, this, &QuarantineWindow::removeAll);
        connect(lookupButton, &QPushButton::clicked, this, &QuarantineWindow::lookupDetection);
        connect(virusTotalButton, &QPushButton::clicked, this, &QuarantineWindow::lookupVirusTotal);
        connect(searchBox, &QLineEdit::textChanged, this, &QuarantineWindow::filterRows);
        connect(table, &QTableWidget::itemSelectionChanged, this, [this] {
            updateActionButtons();
            updateDetails();
        });
        refresh();
        setQuarantineMonitoring(true);
    }

private:
    void setQuarantineWatchPath()
    {
        if (!quarantineWatcher_)
            return;
        for (const QString &path : quarantineWatcher_->directories())
            quarantineWatcher_->removePath(path);
        char path[PATH_MAX];
        if (!clamav_quarantine_path(path))
            return;
        const QString quarantinePath = QString::fromLocal8Bit(path);
        const QString watchPath = QFileInfo::exists(quarantinePath)
            ? quarantinePath : QFileInfo(quarantinePath).absolutePath();
        if (QFileInfo::exists(watchPath))
            quarantineWatcher_->addPath(watchPath);
    }

    void setQuarantineMonitoring(bool enabled)
    {
        if (!enabled) {
            quarantineRefreshTimer_.stop();
            if (quarantineWatcher_) {
                for (const QString &path : quarantineWatcher_->directories())
                    quarantineWatcher_->removePath(path);
            }
            return;
        }
        setQuarantineWatchPath();
        refreshInternal(false);
        quarantineRefreshTimer_.start();
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
        QHash<QString, QColor> entryColors;
        for (const QString &block : blocks) {
            const QStringList lines = block.split(QLatin1Char('\n'));
            if (lines.isEmpty())
                continue;
            QString id;
            for (const QString &line : lines)
                if (line.startsWith(QStringLiteral("  ID: ")))
                    id = line.mid(QStringLiteral("  ID: ").size());
            const bool failed = lines.first().contains(QStringLiteral(" · failed"));
            QColor color = failed ? QColor("#da4453") : QColor("#da4453");
            if (!failed) {
                if (lines.first().contains(QStringLiteral("] restore ")))
                    color = QColor("#d9a441");
                else if (lines.first().contains(QStringLiteral("] delete "))
                             || lines.first().contains(QStringLiteral("] expire ")))
                    color = QColor("#50aa64");
            }
            if (!id.isEmpty())
                entryColors.insert(id, color);
        }
        if (logNewestFirst_)
            std::reverse(blocks.begin(), blocks.end());
        for (const QString &block : blocks) {
            const QStringList lines = block.split(QLatin1Char('\n'));
            if (lines.isEmpty())
                continue;
            QString id;
            for (const QString &line : lines)
                if (line.startsWith(QStringLiteral("  ID: ")))
                    id = line.mid(QStringLiteral("  ID: ").size());
            const bool failed = lines.first().contains(QStringLiteral(" · failed"));
            QColor color = entryColors.value(id, failed ? QColor("#da4453") : QColor("#3daee9"));
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

    void updateManualFileUi()
    {
        const int count = manualFiles->count();
        manualSummaryLabel->setText(count == 0 ? tr("No files selected") : tr("%1 file(s) selected").arg(count));
        manualEmptyLabel->setVisible(count == 0);
        manualRemoveButton->setEnabled(!manualFiles->selectedItems().isEmpty());
        manualQuarantineButton->setEnabled(count > 0);
    }

    void chooseManualFiles()
    {
        const QStringList paths = QFileDialog::getOpenFileNames(this, tr("Choose files to quarantine"));
        for (const QString &path : paths) {
            bool alreadyListed = false;
            for (int row = 0; row < manualFiles->count(); ++row)
                alreadyListed = alreadyListed || manualFiles->item(row)->text() == path;
            if (!alreadyListed)
                manualFiles->addItem(path);
        }
        updateManualFileUi();
    }

    void quarantineManualFiles()
    {
        if (manualFiles->count() == 0)
            return;
        bool removeOriginals = manualRemoveOriginals->isChecked();
        if (removeOriginals) {
            if (QMessageBox::warning(this, tr("Remove original files"),
                        tr("The selected originals will be removed after successful quarantine. Continue?"),
                        QMessageBox::Cancel | QMessageBox::Yes, QMessageBox::Cancel) != QMessageBox::Yes)
                return;
        } else {
            removeOriginals = QMessageBox::question(this, tr("Original files"),
                tr("The checkbox is unchecked, so the original files would normally be kept. Would you like to delete them after successful quarantine?"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes;
        }
        int quarantined = 0;
        int failures = 0;
        QList<QListWidgetItem *> completed;
        for (int row = 0; row < manualFiles->count(); ++row) {
            auto *item = manualFiles->item(row);
            const QString path = item->text();
            char hash[65];
            if (!clamav_quarantine_hash_file(path.toLocal8Bit().constData(), hash)) {
                ++failures;
                continue;
            }
            const QByteArray component = "manual";
            const QByteArray name = QFileInfo(path).fileName().toLocal8Bit();
            const QByteArray source = path.toLocal8Bit();
            const QByteArray detection = "Manually quarantined";
            const clamav_quarantine_metadata metadata{
                component.constData(), name.constData(), source.constData(),
                detection.constData(), hash};
            char id[CLAMAV_QUARANTINE_ID_LENGTH];
            char payload[PATH_MAX];
            if (clamav_quarantine_store(source.constData(), &metadata,
                                        removeOriginals, id, payload)) {
                ++quarantined;
                completed.append(item);
            } else {
                ++failures;
            }
        }
        qDeleteAll(completed);
        refresh();
        updateManualFileUi();
        if (failures > 0)
            QMessageBox::warning(this, tr("Manual quarantine incomplete"),
                tr("%1 file(s) were quarantined and %2 file(s) could not be stored.")
                    .arg(quarantined).arg(failures));
    }

    void refresh()
    {
        refreshInternal(true);
    }

    void refreshInternal(bool showErrors)
    {
        char path[PATH_MAX];
        struct clamav_quarantine_entry *entries = nullptr;
        size_t count = 0;
        if (clamav_quarantine_path(path))
            pathLabel->setText(tr("Location: %1").arg(QString::fromLocal8Bit(path)));
        else
            pathLabel->setText(tr("Location unavailable"));
        if (!clamav_quarantine_list(&entries, &count)) {
            if (showErrors) {
                updateStatusHeader(0, 0, 0, 0);
                QMessageBox::warning(this, tr("Quarantine"), tr("Unable to read the quarantine directory."));
            }
            return;
        }
        QString selectedId;
        if (table->currentRow() >= 0 && table->item(table->currentRow(), 0))
            selectedId = table->item(table->currentRow(), 0)->data(Qt::UserRole).toString();
        const QSignalBlocker signalBlocker(table);
        table->setUpdatesEnabled(false);
        table->setSortingEnabled(false);
        table->setRowCount(0);
        size_t serious = 0;
        size_t review = 0;
        size_t tests = 0;
        size_t pending = 0;
        size_t unknown = 0;
        for (size_t i = 0; i < count; ++i) {
            const auto &entry = entries[i];
            if (!entry.payload_available)
                ++pending;
            switch (threatLevel(QString::fromLocal8Bit(entry.detection))) {
            case 0:
                ++unknown;
                break;
            case 1:
                ++tests;
                break;
            case 2:
                ++review;
                break;
            default:
                ++serious;
                break;
            }
            const int row = table->rowCount();
            table->insertRow(row);
            auto *detectionItem = new QTableWidgetItem(QString::fromLocal8Bit(entry.original_name));
            detectionItem->setToolTip(QString::fromLocal8Bit(entry.detection));
            auto filenameFont = detectionItem->font();
            filenameFont.setBold(true);
            detectionItem->setFont(filenameFont);
            detectionItem->setData(Qt::UserRole, QString::fromLatin1(entry.id));
            detectionItem->setData(Qt::UserRole + 1, QString::fromLocal8Bit(entry.detection));
            detectionItem->setData(Qt::UserRole + 2, QString::fromLocal8Bit(entry.original_name));
            detectionItem->setData(Qt::UserRole + 3, QString::fromLocal8Bit(entry.source));
            detectionItem->setData(Qt::UserRole + 4, QString::fromLatin1(entry.sha256));
            detectionItem->setData(Qt::UserRole + 5, entry.created);
            detectionItem->setData(Qt::UserRole + 6, entry.payload_available);
            detectionItem->setData(Qt::UserRole + 7, QString::fromLocal8Bit(entry.quarantine_reason));
            detectionItem->setData(Qt::UserRole + 8, QString::fromLocal8Bit(entry.origin));
            detectionItem->setData(Qt::UserRole + 9, QString::fromLocal8Bit(entry.metadata));
            if (threatLevel(QString::fromLocal8Bit(entry.detection)) == 0) {
                const QIcon questionIcon = QIcon::fromTheme(QStringLiteral("dialog-question"));
                if (!questionIcon.isNull())
                    detectionItem->setIcon(questionIcon);
                else
                    detectionItem->setText(QStringLiteral("? ") + detectionItem->text());
            }
            table->setItem(row, 0, detectionItem);
            const QString component = QString::fromLocal8Bit(entry.component);
            auto *componentItem = new QTableWidgetItem(entry.payload_available
                ? component : tr("%1 · original not copied").arg(component));
            auto *dateItem = new QTableWidgetItem(entry.created > 0
                ? QDateTime::fromSecsSinceEpoch(entry.created).toString(QStringLiteral("yyyy-MM-dd HH:mm"))
                : QString());
            const QColor tint = threatTint(QString::fromLocal8Bit(entry.detection));
            for (QTableWidgetItem *item : {detectionItem, componentItem, dateItem})
                item->setBackground(tint);
            if (threatLevel(QString::fromLocal8Bit(entry.detection)) == 0) {
                const QBrush unknownBrush(QColor(61, 174, 233));
                for (QTableWidgetItem *item : {detectionItem, componentItem, dateItem})
                    item->setForeground(unknownBrush);
            }
            table->setItem(row, 1, componentItem);
            table->setItem(row, 2, dateItem);
        }
        clamav_quarantine_list_free(entries);
        updateStatusHeader(serious, review, tests, pending, unknown);
        addFromEmptyButton->setVisible(count == 0);
        viewQuarantineButton->setVisible(count > 0);
        table->setSortingEnabled(true);
        table->sortItems(2, Qt::DescendingOrder);
        table->clearSelection();
        if (!selectedId.isEmpty()) {
            for (int row = 0; row < table->rowCount(); ++row) {
                if (table->item(row, 0)->data(Qt::UserRole).toString() == selectedId) {
                    table->selectRow(row);
                    break;
                }
            }
        }
        deleteAllButton->setEnabled(count > 0);
        updateDetails();
        filterRows(searchBox->text());
        table->setUpdatesEnabled(true);
        table->viewport()->update();
    }

    static QString formatSize(long long size)
    {
        if (size < 1024)
            return QObject::tr("%1 B").arg(size);
        if (size < 1024 * 1024)
            return QObject::tr("%1 KiB").arg(size / 1024.0, 0, 'f', 1);
        if (size < 1024LL * 1024 * 1024)
            return QObject::tr("%1 MiB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
        return QObject::tr("%1 GiB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
    }

    void updateStatusHeader(size_t serious, size_t review, size_t tests, size_t pending, size_t unknown = 0)
    {
        if (pending > 0) {
            statusHeaderTitle->setText(tr("Action required"));
            statusHeaderDetails->setText(tr("%1 detection(s) could not be copied into the local quarantine. The original file remains at its source path; review the entry and delete it if appropriate.").arg(pending));
            setStatusHeader(QStringLiteral("dialog-error"), QColor(210, 55, 65));
        } else if (serious > 0) {
            statusHeaderTitle->setText(tr("Action recommended"));
            statusHeaderDetails->setText(tr("%1 serious detection(s) are quarantined. Keep them isolated and review or delete them before continuing.").arg(serious));
            setStatusHeader(QStringLiteral("dialog-error"), QColor(210, 55, 65));
        } else if (review > 0) {
            statusHeaderTitle->setText(tr("Review recommended"));
            statusHeaderDetails->setText(tr("%1 potentially unwanted item(s) are quarantined. They may be unwanted, but are not necessarily malware.").arg(review));
            setStatusHeader(QStringLiteral("dialog-warning"), QColor(220, 170, 30));
        } else if (tests > 0) {
            statusHeaderTitle->setText(tr("No action required"));
            statusHeaderDetails->setText(tr("Only %1 harmless antivirus test signature(s) are quarantined. EICAR files can be safely deleted.").arg(tests));
            setStatusHeader(QStringLiteral("emblem-ok"), QColor(80, 170, 100));
        } else if (unknown > 0) {
            statusHeaderTitle->setText(tr("Unknown"));
            statusHeaderDetails->setText(tr("No quarantined files need your attention."));
            setStatusHeader(QStringLiteral("dialog-question"), QColor(61, 174, 233));
        } else {
            statusHeaderTitle->setText(tr("Quarantine is clear"));
            statusHeaderDetails->setText(tr("No quarantined files need your attention."));
            setStatusHeader(QStringLiteral("emblem-ok"), QColor(80, 170, 100));
        }
    }

    void setStatusHeader(const QString &iconName, const QColor &color)
    {
        statusHeaderIcon->setPixmap(QIcon::fromTheme(iconName).pixmap(28, 28));
        statusHeader->setStyleSheet(QStringLiteral(
            "QFrame#statusHeader { background: rgba(%1, %2, %3, 45); border: 1px solid rgba(%1, %2, %3, 150); border-radius: 8px; }"
            "QFrame#statusHeader QLabel { border: none; background: transparent; color: palette(window-text); }")
            .arg(color.red()).arg(color.green()).arg(color.blue()));
    }

    void filterRows(const QString &text)
    {
        const QString filter = text.trimmed();
        for (int row = 0; row < table->rowCount(); ++row) {
            QStringList values;
            for (int column = 0; column < table->columnCount(); ++column)
                values << table->item(row, column)->text();
            values << table->item(row, 0)->data(Qt::UserRole + 1).toString();
            table->setRowHidden(row, !filter.isEmpty()
                && !values.join(QStringLiteral(" ")).contains(filter, Qt::CaseInsensitive));
        }
    }

    QString selectedId() const
    {
        const auto *item = table->item(table->currentRow(), 0);
        return item ? item->data(Qt::UserRole).toString() : QString();
    }

    QList<int> selectedRows() const
    {
        QList<int> rows;
        for (const QModelIndex &index : table->selectionModel()->selectedRows())
            rows << index.row();
        return rows;
    }

    void updateActionButtons()
    {
        const QList<int> rows = selectedRows();
        const int selected = rows.size();
        bool allPayloadsAvailable = selected > 0;
        for (const int row : rows) {
            const auto *item = row >= 0 ? table->item(row, 0) : nullptr;
            allPayloadsAvailable = allPayloadsAvailable
                && item != nullptr && item->data(Qt::UserRole + 6).toBool();
        }
        restoreButton->setEnabled(allPayloadsAvailable);
        deleteButton->setEnabled(selected > 0);
        const auto *currentItem = table->currentRow() >= 0 ? table->item(table->currentRow(), 0) : nullptr;
        deleteButton->setText(selected == 1 && currentItem != nullptr
            && !currentItem->data(Qt::UserRole + 6).toBool()
            ? tr("Delete original") : tr("Delete permanently"));
        lookupButton->setEnabled(selected == 1);
        virusTotalButton->setEnabled(selected == 1 && itemHashIsValid());
    }

    void updateDetails()
    {
        if (selectedRows().isEmpty()) {
            emptyState->setVisible(true);
            detailContent->setVisible(false);
            componentLabel->setText(tr("Select an item"));
            originalLabel->clear();
            sourceLabel->clear();
            originLabel->clear();
            metadataLabel->clear();
            hashLabel->clear();
            createdLabel->clear();
            descriptionLabel->clear();
            severityLabel->clear();
            severityMeter->setValue(0);
            details->clear();
            return;
        }
        int row = table->currentRow();
        if (row < 0 || !table->item(row, 0))
            row = selectedRows().first();
        const auto *item = row >= 0 ? table->item(row, 0) : nullptr;
        if (!item) {
            emptyState->setVisible(true);
            detailContent->setVisible(false);
            componentLabel->setText(tr("Select an item"));
            originalLabel->clear();
            sourceLabel->clear();
            originLabel->clear();
            metadataLabel->clear();
            hashLabel->clear();
            createdLabel->clear();
            descriptionLabel->clear();
            severityLabel->clear();
            severityMeter->setValue(0);
            details->clear();
            return;
        }
        emptyState->setVisible(false);
        detailContent->setVisible(true);
        const auto *componentItem = table->item(row, 1);
        componentLabel->setText(componentItem ? componentItem->text() : tr("Unknown"));
        originalLabel->setText(item->data(Qt::UserRole + 2).toString());
        sourceLabel->setText(item->data(Qt::UserRole + 3).toString());
        originLabel->setText(item->data(Qt::UserRole + 8).toString());
        metadataLabel->setText(formattedMetadata(item->data(Qt::UserRole + 9).toString()));
        hashLabel->setText(item->data(Qt::UserRole + 4).toString());
        const auto created = item->data(Qt::UserRole + 5).toLongLong();
        createdLabel->setText(created > 0 ? QDateTime::fromSecsSinceEpoch(created).toString(Qt::TextDate) : tr("Unknown"));
        const QString report = item->data(Qt::UserRole + 1).toString();
        const int level = threatLevel(report);
        const QColor tint = threatTint(report);
        severityLabel->setText(tr("Threat level: %1").arg(threatLabel(report)));
        severityLabel->setStyleSheet(QStringLiteral("font-weight: 600; color: rgb(%1, %2, %3);")
            .arg(tint.red()).arg(tint.green()).arg(tint.blue()));
        severityMeter->setValue(level);
        severityMeter->setStyleSheet(QStringLiteral(
            "QProgressBar { border: 0; border-radius: 4px; background: palette(midlight); }"
            "QProgressBar::chunk { border-radius: 4px; background: rgb(%1, %2, %3); }")
            .arg(tint.red()).arg(tint.green()).arg(tint.blue()));
        const bool payloadAvailable = item->data(Qt::UserRole + 6).toBool();
        const QString reason = item->data(Qt::UserRole + 7).toString();
        descriptionLabel->setText(payloadAvailable
            ? localDescription(report)
            : tr("This detection was recorded, but the file was not copied into the local quarantine%1. The original remains at the source path. Use “Delete original” only if you want to remove it permanently.")
                .arg(reason.isEmpty() ? QString() : tr(" (%1)").arg(reason)));
        details->setPlainText(report);
    }

    bool itemHashIsValid() const
    {
        const auto *item = table->item(table->currentRow(), 0);
        return item != nullptr && QRegularExpression(QStringLiteral("^[0-9a-fA-F]{64}$"))
            .match(item->data(Qt::UserRole + 4).toString()).hasMatch();
    }

    void restore()
    {
        const QList<int> rows = selectedRows();
        if (rows.isEmpty())
            return;
        if (rows.size() == 1) {
            const auto *item = table->item(rows.first(), 0);
            const QString sourcePath = item->data(Qt::UserRole + 3).toString();
            const QString originalName = QFileInfo(item->data(Qt::UserRole + 2).toString()).fileName();
            const QString originalDirectory = QFileInfo(sourcePath).absolutePath();
            const QString initialPath = !originalName.isEmpty() && QDir(originalDirectory).exists()
                ? QDir(originalDirectory).filePath(originalName) : originalName;
            const QString destination = QFileDialog::getSaveFileName(this, tr("Restore quarantined file"), initialPath);
            if (destination.isEmpty())
                return;
            const QString id = item->data(Qt::UserRole).toString();
            if (!clamav_quarantine_restore(id.toLatin1().constData(), destination.toLocal8Bit().constData()))
                QMessageBox::warning(this, tr("Restore failed"), tr("The destination already exists or the quarantined file could not be restored."));
            else
                refresh();
            return;
        }
        if (QMessageBox::question(this, tr("Restore multiple files"),
                tr("Restore %1 quarantined files? Existing destination files will not be overwritten.").arg(rows.size())) != QMessageBox::Yes)
            return;
        const QString directory = QFileDialog::getExistingDirectory(this, tr("Choose restore directory"));
        if (directory.isEmpty())
            return;
        int failures = 0;
        for (const int row : rows) {
            const auto *item = table->item(row, 0);
            const QString id = item->data(Qt::UserRole).toString();
            const QString name = item->data(Qt::UserRole + 2).toString();
            if (!clamav_quarantine_restore(id.toLatin1().constData(), QDir(directory).filePath(name).toLocal8Bit().constData()))
                ++failures;
        }
        refresh();
        if (failures > 0)
            QMessageBox::warning(this, tr("Restore incomplete"), tr("%1 file(s) could not be restored.").arg(failures));
    }

    void remove()
    {
        const QList<int> rows = selectedRows();
        if (rows.isEmpty())
            return;
        bool hasPending = false;
        for (const int row : rows)
            hasPending = hasPending || !table->item(row, 0)->data(Qt::UserRole + 6).toBool();
        const QString prompt = rows.size() == 1
            ? (hasPending ? tr("Delete the original file permanently? This cannot be undone.")
                          : tr("Delete this quarantined file permanently?"))
            : (hasPending ? tr("Delete %1 selected files or their original paths permanently?").arg(rows.size())
                          : tr("Delete %1 quarantined files permanently?").arg(rows.size()));
        if (QMessageBox::question(this, tr("Delete quarantined files"), prompt) != QMessageBox::Yes)
            return;
        int failures = 0;
        for (const int row : rows) {
            const QString id = table->item(row, 0)->data(Qt::UserRole).toString();
            if (!clamav_quarantine_delete(id.toLatin1().constData()))
                ++failures;
        }
        refresh();
        if (failures > 0)
            QMessageBox::warning(this, tr("Delete incomplete"), tr("%1 quarantined file(s) could not be deleted.").arg(failures));
    }

    void removeAll()
    {
        if (table->rowCount() == 0
                || QMessageBox::warning(this, tr("Delete all quarantined files"),
                tr("Delete every quarantined file and every recorded original permanently? This cannot be undone."),
                    QMessageBox::Cancel | QMessageBox::Yes, QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        QStringList ids;
        for (int row = 0; row < table->rowCount(); ++row)
            if (const auto *item = table->item(row, 0))
                ids << item->data(Qt::UserRole).toString();
        int failures = 0;
        for (const QString &id : ids)
            if (!clamav_quarantine_delete(id.toLatin1().constData()))
                ++failures;
        refresh();
        if (failures > 0)
            QMessageBox::warning(this, tr("Delete incomplete"),
                tr("%1 quarantined file(s) could not be deleted.").arg(failures));
    }

    void lookupDetection()
    {
        const auto *item = table->item(table->currentRow(), 0);
        if (!item)
            return;
        QString detection = item->data(Qt::UserRole + 1).toString().split('\n').value(0).trimmed();
        const int separator = detection.lastIndexOf(QStringLiteral(": "));
        if (separator >= 0)
            detection = detection.mid(separator + 2);
        detection.remove(QRegularExpression(QStringLiteral("\\s+FOUND$"), QRegularExpression::CaseInsensitiveOption));
        if (detection.isEmpty())
            return;
        const QByteArray encoded = QUrl::toPercentEncoding(detection.left(256));
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://duckduckgo.com/?q=ClamAV+") + QString::fromLatin1(encoded)));
        clamav_quarantine_audit("lookup-web", item->data(Qt::UserRole).toString().toLatin1().constData(),
                                table->item(table->currentRow(), 1)->text().toLatin1().constData(),
                                item->data(Qt::UserRole + 3).toString().toLocal8Bit().constData(),
                                detection.toLocal8Bit().constData(), 1);
    }

    void lookupVirusTotal()
    {
        const auto *item = table->item(table->currentRow(), 0);
        if (!item || !itemHashIsValid())
            return;
        const QString hash = item->data(Qt::UserRole + 4).toString().toLower();
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://www.virustotal.com/gui/file/") + hash + QStringLiteral("/detection")));
        clamav_quarantine_audit("lookup-virustotal", item->data(Qt::UserRole).toString().toLatin1().constData(),
                                table->item(table->currentRow(), 1)->text().toLatin1().constData(),
                                item->data(Qt::UserRole + 3).toString().toLocal8Bit().constData(),
                                hash.toLatin1().constData(), 1);
    }

    QLabel *pathLabel;
    QTableWidget *table;
    QLineEdit *searchBox;
    QFrame *statusHeader;
    QLabel *statusHeaderQuarantineIcon;
    QLabel *statusHeaderIcon;
    QLabel *statusHeaderTitle;
    QLabel *statusHeaderDetails;
    QPushButton *addFromEmptyButton;
    QTabWidget *tabs_ = nullptr;
    QPushButton *viewQuarantineButton;
    QPushButton *refreshButton;
    QPushButton *restoreButton;
    QPushButton *deleteButton;
    QPushButton *deleteAllButton;
    QPushButton *lookupButton;
    QLabel *componentLabel;
    QLabel *originalLabel;
    QLabel *sourceLabel;
    QLabel *originLabel;
    QLabel *metadataLabel;
    QLabel *hashLabel;
    QLabel *createdLabel;
    QLabel *descriptionLabel;
    QLabel *severityLabel;
    QProgressBar *severityMeter;
    QTextEdit *details;
    QPushButton *virusTotalButton;
    QLabel *emptyState;
    QWidget *detailContent;
    QWidget *quarantinePage_ = nullptr;
    QListWidget *manualFiles;
    QLabel *manualSummaryLabel;
    QLabel *manualEmptyLabel;
    QPushButton *manualChooseButton;
    QPushButton *manualRemoveButton;
    QPushButton *manualQuarantineButton;
    QCheckBox *manualRemoveOriginals;
    QListWidget *logView_ = nullptr;
    QLineEdit *logFilter_ = nullptr;
    QPushButton *logRefreshButton_ = nullptr;
    QFileSystemWatcher *logWatcher_ = nullptr;
    QTimer logRefreshTimer_;
    QString logPath_;
    bool logNewestFirst_ = true;
    QFileSystemWatcher *quarantineWatcher_ = nullptr;
    QTimer quarantineRefreshTimer_;
};

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    std::unique_ptr<QLockFile> instanceLock;
    if (::geteuid() != 0) {
        QString lockDirectory = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        if (lockDirectory.isEmpty())
            lockDirectory = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
        const QString lockPath = QDir(lockDirectory).filePath(
            QStringLiteral("clamav-quarantine-gui-%1.lock").arg(::getuid()));
        instanceLock = std::make_unique<QLockFile>(lockPath);
        if (!instanceLock->tryLock(0)) {
            QMessageBox::warning(nullptr, QObject::tr("ClamAV Quarantine"),
                                 QObject::tr("The quarantine window is already open for this user."));
            return 1;
        }
    }
    QTranslator dutch;
    if (QLocale().language() == QLocale::Dutch
            && dutch.load(QStringLiteral("clamav-quarantine_nl"), QStringLiteral(CLAMAV_TRANSLATION_DIR)))
        application.installTranslator(&dutch);
    application.setDesktopFileName(QStringLiteral("clamav-quarantine"));
    QuarantineWindow window;
    window.setWindowIcon(QIcon::fromTheme(QStringLiteral("clamav-quarantine"),
                                          QIcon::fromTheme(QStringLiteral("clamav"))));
    window.show();
    return application.exec();
}
