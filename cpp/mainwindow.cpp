#include "mainwindow.h"

#include "filefish/src/bridge.cxx.h"
#include "rust/cxx.h"

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QFont>
#include <QKeySequence>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTreeWidget>

#include <vector>

namespace
{

void openFile(QWidget *parent, QTreeWidget *tree, QPlainTextEdit *dataView)
{
    const QString path = QFileDialog::getOpenFileName(parent, "Open File");
    if (path.isEmpty()) {
        return;
    }

    FileInfo fileInfo;
    try {
        fileInfo = dissect_file(rust::Str(path.toStdString()));
    } catch (const rust::Error &e) {
        return;
    }

    tree->clear();

    std::vector<QTreeWidgetItem *> items(fileInfo.blocks.size(), nullptr);
    for (size_t i = 0; i < fileInfo.blocks.size(); ++i) {
        const auto &block = fileInfo.blocks[i];
        QTreeWidgetItem *parent = block.parent >= 0 ? items[block.parent] : tree->invisibleRootItem();
        auto *item = new QTreeWidgetItem(parent, {QString::fromStdString(std::string(block.label))});
        item->setData(0, Qt::UserRole, static_cast<quint64>(block.start));
        item->setData(0, Qt::UserRole + 1, static_cast<quint64>(block.end));
        if (!block.expandable) {
            item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
        }
        items[i] = item;
    }

    tree->expandAll();

    dataView->setPlainText(QString::fromStdString(std::string(fileInfo.hex_dump)));
}

} // namespace

int run_app()
{
    int argc = 0;
    QApplication app(argc, nullptr);

    QMainWindow window;
    window.setWindowTitle("filefish");
    window.resize(1024, 768);

    auto *splitter = new QSplitter(&window);

    auto *tree = new QTreeWidget(splitter);
    tree->setColumnCount(1);
    tree->setHeaderHidden(true);

    auto *dataView = new QPlainTextEdit(splitter);
    dataView->setReadOnly(true);
    dataView->setPlaceholderText("Data view");
    dataView->setFont(QFont("monospace"));

    splitter->addWidget(tree);
    splitter->addWidget(dataView);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 2);

    window.setCentralWidget(splitter);

    QMenu *fileMenu = window.menuBar()->addMenu("&File");
    QAction *openAction = fileMenu->addAction("&Open...");
    openAction->setShortcut(QKeySequence::Open);
    QObject::connect(openAction, &QAction::triggered, &window, [&window, tree, dataView]() {
        openFile(&window, tree, dataView);
    });

    window.show();

    return app.exec();
}
