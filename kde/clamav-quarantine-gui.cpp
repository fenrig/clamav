/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#include "quarantine.h"

#include <QApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QFormLayout>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPushButton>
#include <QRegularExpression>
#include <QSplitter>
#include <QTextEdit>
#include <QUrl>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

static QString localDescription(const QString &detection)
{
    const QString name = detection.section('\n', 0, 0).section(QStringLiteral(": "), -1).trimmed();
    if (name.startsWith(QStringLiteral("Eicar-Signature"), Qt::CaseInsensitive))
        return QObject::tr("This is the standard harmless EICAR antivirus test file, not a real infection.");
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

class DeselectableTableWidget final : public QTableWidget
{
public:
    using QTableWidget::QTableWidget;

protected:
    void mousePressEvent(QMouseEvent *event) override
    {
        const QModelIndex index = indexAt(event->position().toPoint());
        if (!index.isValid() || selectionModel()->isSelected(index)) {
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
        componentLabel = new QLabel(tr("Select an item"), this);
        originalLabel = new QLabel(this);
        sourceLabel = new QLabel(this);
        hashLabel = new QLabel(this);
        createdLabel = new QLabel(this);
        descriptionLabel = new QLabel(this);
        details = new QTextEdit(this);
        refreshButton = new QPushButton(tr("Refresh"), this);
        restoreButton = new QPushButton(tr("Restore…"), this);
        deleteButton = new QPushButton(tr("Delete permanently"), this);
        lookupButton = new QPushButton(tr("Look up detection"), this);
        virusTotalButton = new QPushButton(tr("Open VirusTotal"), this);

        table->setColumnCount(5);
        table->setHorizontalHeaderLabels({tr("Detection"), tr("Original name"), tr("Component"), tr("Created"), tr("Size")});
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->verticalHeader()->setVisible(false);
        restoreButton->setEnabled(false);
        deleteButton->setEnabled(false);
        lookupButton->setEnabled(false);
        virusTotalButton->setEnabled(false);
        details->setReadOnly(true);
        details->setMinimumHeight(140);
        sourceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        hashLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        descriptionLabel->setWordWrap(true);

        auto *detailWidget = new QWidget(this);
        auto *detailLayout = new QVBoxLayout(detailWidget);
        auto *detailTitle = new QLabel(tr("Detection details"), detailWidget);
        detailTitle->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: 600;"));
        auto *form = new QFormLayout;
        form->addRow(tr("Component:"), componentLabel);
        form->addRow(tr("Original name:"), originalLabel);
        form->addRow(tr("Source path:"), sourceLabel);
        form->addRow(tr("SHA-256:"), hashLabel);
        form->addRow(tr("Created:"), createdLabel);
        detailLayout->addWidget(detailTitle);
        detailLayout->addLayout(form);
        detailLayout->addWidget(new QLabel(tr("Summary:"), detailWidget));
        detailLayout->addWidget(descriptionLabel);
        detailLayout->addWidget(new QLabel(tr("ClamAV report:"), detailWidget));
        detailLayout->addWidget(details, 1);

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
        splitter->setStretchFactor(0, 1);
        splitter->setStretchFactor(1, 2);

        layout->addWidget(new QLabel(tr("User quarantine (payloads are never opened by this application)"), this));
        layout->addWidget(pathLabel);
        layout->addWidget(splitter, 1);
        toolbar->addWidget(refreshButton);
        toolbar->addStretch();
        toolbar->addWidget(restoreButton);
        toolbar->addWidget(deleteButton);
        toolbar->addWidget(lookupButton);
        toolbar->addWidget(virusTotalButton);
        layout->addLayout(toolbar);
        setCentralWidget(central);
        setWindowTitle(tr("ClamAV Quarantine"));
        resize(1000, 500);

        connect(refreshButton, &QPushButton::clicked, this, &QuarantineWindow::refresh);
        connect(restoreButton, &QPushButton::clicked, this, &QuarantineWindow::restore);
        connect(deleteButton, &QPushButton::clicked, this, &QuarantineWindow::remove);
        connect(lookupButton, &QPushButton::clicked, this, &QuarantineWindow::lookupDetection);
        connect(virusTotalButton, &QPushButton::clicked, this, &QuarantineWindow::lookupVirusTotal);
        connect(searchBox, &QLineEdit::textChanged, this, &QuarantineWindow::filterRows);
        connect(table, &QTableWidget::itemSelectionChanged, this, [this] {
            const bool selected = table->currentRow() >= 0;
            restoreButton->setEnabled(selected);
            deleteButton->setEnabled(selected);
            lookupButton->setEnabled(selected);
            virusTotalButton->setEnabled(selected && itemHashIsValid());
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
            QMessageBox::warning(this, tr("Quarantine"), tr("Unable to read the quarantine directory."));
            return;
        }
        for (size_t i = 0; i < count; ++i) {
            const auto &entry = entries[i];
            const int row = table->rowCount();
            table->insertRow(row);
            auto *detectionItem = new QTableWidgetItem(QString::fromLocal8Bit(entry.detection).split('\n').value(0));
            detectionItem->setData(Qt::UserRole, QString::fromLatin1(entry.id));
            detectionItem->setData(Qt::UserRole + 1, QString::fromLocal8Bit(entry.detection));
            detectionItem->setData(Qt::UserRole + 2, QString::fromLocal8Bit(entry.original_name));
            detectionItem->setData(Qt::UserRole + 3, QString::fromLocal8Bit(entry.source));
            detectionItem->setData(Qt::UserRole + 4, QString::fromLatin1(entry.sha256));
            detectionItem->setData(Qt::UserRole + 5, entry.created);
            table->setItem(row, 0, detectionItem);
            auto *nameItem = new QTableWidgetItem(QString::fromLocal8Bit(entry.original_name));
            nameItem->setData(Qt::UserRole, QString::fromLatin1(entry.id));
            table->setItem(row, 1, nameItem);
            table->setItem(row, 2, new QTableWidgetItem(QString::fromLocal8Bit(entry.component)));
            table->setItem(row, 3, new QTableWidgetItem(entry.created > 0
                ? QDateTime::fromSecsSinceEpoch(entry.created).toString(Qt::TextDate)
                : tr("Unknown")));
            table->setItem(row, 4, new QTableWidgetItem(formatSize(entry.size)));
        }
        clamav_quarantine_list_free(entries);
        table->setSortingEnabled(true);
        table->clearSelection();
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

    void updateDetails()
    {
        const int row = table->currentRow();
        const auto *item = row >= 0 ? table->item(row, 0) : nullptr;
        if (!item) {
            componentLabel->setText(tr("Select an item"));
            originalLabel->clear();
            sourceLabel->clear();
            hashLabel->clear();
            createdLabel->clear();
            descriptionLabel->clear();
            details->clear();
            return;
        }
        componentLabel->setText(table->item(row, 2)->text());
        originalLabel->setText(item->data(Qt::UserRole + 2).toString());
        sourceLabel->setText(item->data(Qt::UserRole + 3).toString());
        hashLabel->setText(item->data(Qt::UserRole + 4).toString());
        const auto created = item->data(Qt::UserRole + 5).toLongLong();
        createdLabel->setText(created > 0 ? QDateTime::fromSecsSinceEpoch(created).toString(Qt::TextDate) : tr("Unknown"));
        const QString report = item->data(Qt::UserRole + 1).toString();
        descriptionLabel->setText(localDescription(report));
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
        const QString id = selectedId();
        if (id.isEmpty())
            return;
        const QString destination = QFileDialog::getSaveFileName(this, tr("Restore quarantined file"));
        if (destination.isEmpty())
            return;
        if (!clamav_quarantine_restore(id.toLatin1().constData(), destination.toLocal8Bit().constData()))
            QMessageBox::warning(this, tr("Restore failed"), tr("The destination already exists or the quarantined file could not be restored."));
        else
            refresh();
    }

    void remove()
    {
        const QString id = selectedId();
        if (id.isEmpty() || QMessageBox::question(this, tr("Delete quarantined file"),
                tr("Delete this quarantined file permanently?")) != QMessageBox::Yes)
            return;
        if (!clamav_quarantine_delete(id.toLatin1().constData()))
            QMessageBox::warning(this, tr("Delete failed"), tr("The quarantined file could not be deleted."));
        else
            refresh();
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
    }

    void lookupVirusTotal()
    {
        const auto *item = table->item(table->currentRow(), 0);
        if (!item || !itemHashIsValid())
            return;
        const QString hash = item->data(Qt::UserRole + 4).toString().toLower();
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://www.virustotal.com/gui/file/") + hash + QStringLiteral("/detection")));
    }

    QLabel *pathLabel;
    QTableWidget *table;
    QLineEdit *searchBox;
    QPushButton *refreshButton;
    QPushButton *restoreButton;
    QPushButton *deleteButton;
    QPushButton *lookupButton;
    QLabel *componentLabel;
    QLabel *originalLabel;
    QLabel *sourceLabel;
    QLabel *hashLabel;
    QLabel *createdLabel;
    QLabel *descriptionLabel;
    QTextEdit *details;
    QPushButton *virusTotalButton;
};

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    QuarantineWindow window;
    window.show();
    return application.exec();
}
