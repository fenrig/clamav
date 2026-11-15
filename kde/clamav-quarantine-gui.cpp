/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#include "quarantine.h"

#include <QApplication>
#include <QColor>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFormLayout>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPushButton>
#include <QProgressBar>
#include <QRegularExpression>
#include <QFrame>
#include <QSplitter>
#include <QTextEdit>
#include <QUrl>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

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

static int threatLevel(const QString &detection)
{
    const QString name = detection.section('\n', 0, 0).section(QStringLiteral(": "), -1).trimmed();
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
        auto *layout = new QVBoxLayout(central);
        auto *toolbar = new QHBoxLayout;
        auto *listToolbar = new QHBoxLayout;
        pathLabel = new QLabel(this);
        table = new DeselectableTableWidget(this);
        searchBox = new QLineEdit(this);
        searchBox->setPlaceholderText(tr("Search detections, filenames, or components…"));
        statusHeader = new QFrame(this);
        statusHeader->setObjectName(QStringLiteral("statusHeader"));
        statusHeaderIcon = new QLabel(statusHeader);
        statusHeaderIcon->setFixedSize(32, 32);
        statusHeaderIcon->setAlignment(Qt::AlignCenter);
        statusHeaderTitle = new QLabel(statusHeader);
        statusHeaderDetails = new QLabel(statusHeader);
        componentLabel = new QLabel(tr("Select an item"), this);
        originalLabel = new QLabel(this);
        sourceLabel = new QLabel(this);
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
        listLayout->addWidget(new QLabel(tr("Quarantined detections"), listWidget));
        listToolbar->addWidget(searchBox);
        listToolbar->addWidget(new QLabel(tr("Filter"), listWidget));
        listLayout->addLayout(listToolbar);
        listLayout->addWidget(table);
        splitter->addWidget(listWidget);
        splitter->addWidget(detailWidget);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        splitter->setSizes({600, 400});

        auto *intro = new QLabel(tr("User quarantine · payloads are never opened by this application"), this);
        intro->setStyleSheet(QStringLiteral("color: palette(mid);"));
        layout->addWidget(intro);
        auto *statusLayout = new QHBoxLayout(statusHeader);
        statusLayout->setContentsMargins(16, 12, 16, 12);
        statusLayout->addWidget(statusHeaderIcon);
        auto *statusText = new QVBoxLayout;
        statusHeaderTitle->setStyleSheet(QStringLiteral("font-size: 16px; font-weight: 600; color: palette(window-text); border: none; background: transparent;"));
        statusHeaderDetails->setWordWrap(true);
        statusHeaderDetails->setStyleSheet(QStringLiteral("color: palette(window-text); border: none; background: transparent;"));
        statusText->addWidget(statusHeaderTitle);
        statusText->addWidget(statusHeaderDetails);
        statusLayout->addLayout(statusText, 1);
        layout->addWidget(statusHeader);
        layout->addWidget(pathLabel);
        layout->addWidget(splitter, 1);
        toolbar->addWidget(refreshButton);
        toolbar->addStretch();
        toolbar->addWidget(restoreButton);
        toolbar->addWidget(deleteButton);
        toolbar->addWidget(deleteAllButton);
        toolbar->addWidget(lookupButton);
        toolbar->addWidget(virusTotalButton);
        layout->addLayout(toolbar);
        setCentralWidget(central);
        setWindowTitle(tr("ClamAV Quarantine"));
        resize(1000, 500);
        setStyleSheet(QStringLiteral(
            "QFrame#summaryCard { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#reportCard { background: palette(base); border: 1px solid palette(mid); border-radius: 8px; }"
            "QFrame#summaryCard QLabel, QFrame#reportCard QLabel { border: none; }"
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
    }

private:
    void refresh()
    {
        char path[PATH_MAX];
        struct clamav_quarantine_entry *entries = nullptr;
        size_t count = 0;
        table->setSortingEnabled(false);
        table->setRowCount(0);
        if (clamav_quarantine_path(path))
            pathLabel->setText(tr("Location: %1").arg(QString::fromLocal8Bit(path)));
        else
            pathLabel->setText(tr("Location unavailable"));
        if (!clamav_quarantine_list(&entries, &count)) {
            updateStatusHeader(0, 0, 0, 0);
            QMessageBox::warning(this, tr("Quarantine"), tr("Unable to read the quarantine directory."));
            return;
        }
        size_t serious = 0;
        size_t review = 0;
        size_t tests = 0;
        size_t pending = 0;
        for (size_t i = 0; i < count; ++i) {
            const auto &entry = entries[i];
            if (!entry.payload_available)
                ++pending;
            switch (threatLevel(QString::fromLocal8Bit(entry.detection))) {
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
            table->setItem(row, 1, componentItem);
            table->setItem(row, 2, dateItem);
        }
        clamav_quarantine_list_free(entries);
        updateStatusHeader(serious, review, tests, pending);
        table->setSortingEnabled(true);
        table->sortItems(2, Qt::DescendingOrder);
        table->clearSelection();
        deleteAllButton->setEnabled(count > 0);
        updateDetails();
        filterRows(searchBox->text());
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

    void updateStatusHeader(size_t serious, size_t review, size_t tests, size_t pending)
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
        const int selected = selectedRows().size();
        bool allPayloadsAvailable = selected > 0;
        for (const int row : selectedRows())
            allPayloadsAvailable = allPayloadsAvailable
                && table->item(row, 0)->data(Qt::UserRole + 6).toBool();
        restoreButton->setEnabled(allPayloadsAvailable);
        deleteButton->setEnabled(selected > 0);
        deleteButton->setText(selected == 1
            && !table->item(table->currentRow(), 0)->data(Qt::UserRole + 6).toBool()
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
            hashLabel->clear();
            createdLabel->clear();
            descriptionLabel->clear();
            severityLabel->clear();
            severityMeter->setValue(0);
            details->clear();
            return;
        }
        const int row = table->currentRow();
        const auto *item = row >= 0 ? table->item(row, 0) : nullptr;
        if (!item) {
            emptyState->setVisible(true);
            detailContent->setVisible(false);
            componentLabel->setText(tr("Select an item"));
            originalLabel->clear();
            sourceLabel->clear();
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
        componentLabel->setText(table->item(row, 1)->text());
        originalLabel->setText(item->data(Qt::UserRole + 2).toString());
        sourceLabel->setText(item->data(Qt::UserRole + 3).toString());
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
            const QString destination = QFileDialog::getSaveFileName(this, tr("Restore quarantined file"));
            if (destination.isEmpty())
                return;
            const QString id = table->item(rows.first(), 0)->data(Qt::UserRole).toString();
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
    QLabel *statusHeaderIcon;
    QLabel *statusHeaderTitle;
    QLabel *statusHeaderDetails;
    QPushButton *refreshButton;
    QPushButton *restoreButton;
    QPushButton *deleteButton;
    QPushButton *deleteAllButton;
    QPushButton *lookupButton;
    QLabel *componentLabel;
    QLabel *originalLabel;
    QLabel *sourceLabel;
    QLabel *hashLabel;
    QLabel *createdLabel;
    QLabel *descriptionLabel;
    QLabel *severityLabel;
    QProgressBar *severityMeter;
    QTextEdit *details;
    QPushButton *virusTotalButton;
    QLabel *emptyState;
    QWidget *detailContent;
};

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setDesktopFileName(QStringLiteral("clamav-quarantine"));
    QuarantineWindow window;
    window.setWindowIcon(QIcon::fromTheme(QStringLiteral("clamav-quarantine"),
                                          QIcon::fromTheme(QStringLiteral("clamav"))));
    window.show();
    return application.exec();
}
