/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#include "quarantine.h"

#include <QApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMainWindow>
#include <QMessageBox>
#include <QPushButton>
#include <QUrl>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

class QuarantineWindow final : public QMainWindow
{
public:
    QuarantineWindow()
    {
        auto *central = new QWidget(this);
        auto *layout = new QVBoxLayout(central);
        auto *toolbar = new QHBoxLayout;
        pathLabel = new QLabel(this);
        table = new QTableWidget(this);
        refreshButton = new QPushButton(tr("Refresh"), this);
        restoreButton = new QPushButton(tr("Restore…"), this);
        deleteButton = new QPushButton(tr("Delete permanently"), this);
        lookupButton = new QPushButton(tr("Look up detection"), this);

        table->setColumnCount(6);
        table->setHorizontalHeaderLabels({tr("Detection"), tr("Component"), tr("Original name"),
                                          tr("Source path"), tr("SHA-256"), tr("Created")});
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        table->verticalHeader()->setVisible(false);
        restoreButton->setEnabled(false);
        deleteButton->setEnabled(false);
        lookupButton->setEnabled(false);

        layout->addWidget(new QLabel(tr("User quarantine (payloads are never opened by this application)"), this));
        layout->addWidget(pathLabel);
        layout->addWidget(table);
        toolbar->addWidget(refreshButton);
        toolbar->addStretch();
        toolbar->addWidget(restoreButton);
        toolbar->addWidget(deleteButton);
        toolbar->addWidget(lookupButton);
        layout->addLayout(toolbar);
        setCentralWidget(central);
        setWindowTitle(tr("ClamAV Quarantine"));
        resize(1000, 500);

        connect(refreshButton, &QPushButton::clicked, this, &QuarantineWindow::refresh);
        connect(restoreButton, &QPushButton::clicked, this, &QuarantineWindow::restore);
        connect(deleteButton, &QPushButton::clicked, this, &QuarantineWindow::remove);
        connect(lookupButton, &QPushButton::clicked, this, &QuarantineWindow::lookupDetection);
        connect(table, &QTableWidget::itemSelectionChanged, this, [this] {
            const bool selected = table->currentRow() >= 0;
            restoreButton->setEnabled(selected);
            deleteButton->setEnabled(selected);
            lookupButton->setEnabled(selected);
        });
        refresh();
    }

private:
    void refresh()
    {
        char path[PATH_MAX];
        struct clamav_quarantine_entry *entries = nullptr;
        size_t count = 0;
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
            table->setItem(row, 0, new QTableWidgetItem(QString::fromLocal8Bit(entry.detection)));
            table->setItem(row, 1, new QTableWidgetItem(QString::fromLocal8Bit(entry.component)));
            table->setItem(row, 2, new QTableWidgetItem(QString::fromLocal8Bit(entry.original_name)));
            table->setItem(row, 3, new QTableWidgetItem(QString::fromLocal8Bit(entry.source)));
            table->setItem(row, 4, new QTableWidgetItem(QString::fromLatin1(entry.sha256)));
            table->setItem(row, 5, new QTableWidgetItem(entry.created > 0
                ? QDateTime::fromSecsSinceEpoch(entry.created).toString(Qt::TextDate)
                : tr("Unknown")));
            table->item(row, 0)->setData(Qt::UserRole, QString::fromLatin1(entry.id));
        }
        clamav_quarantine_list_free(entries);
        table->clearSelection();
    }

    QString selectedId() const
    {
        const auto *item = table->item(table->currentRow(), 0);
        return item ? item->data(Qt::UserRole).toString() : QString();
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
        QString detection = item->text().split('\n').value(0).trimmed();
        const int separator = detection.lastIndexOf(QStringLiteral(": "));
        if (separator >= 0)
            detection = detection.mid(separator + 2);
        detection.remove(QRegularExpression(QStringLiteral("\\s+FOUND$"), QRegularExpression::CaseInsensitiveOption));
        if (detection.isEmpty())
            return;
        const QByteArray encoded = QUrl::toPercentEncoding(detection.left(256));
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://duckduckgo.com/?q=ClamAV+") + QString::fromLatin1(encoded)));
    }

    QLabel *pathLabel;
    QTableWidget *table;
    QPushButton *refreshButton;
    QPushButton *restoreButton;
    QPushButton *deleteButton;
    QPushButton *lookupButton;
};

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    QuarantineWindow window;
    window.show();
    return application.exec();
}
