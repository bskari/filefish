#include "mainwindow.h"

#include "filefish/src/bridge.cxx.h"
#include "rust/cxx.h"

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QKeySequence>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTreeWidget>

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

    const QFileInfo info(path);

    tree->clear();
    auto *root = new QTreeWidgetItem(tree, {"File", info.fileName()});
    new QTreeWidgetItem(root, {"Path", info.absoluteFilePath()});
    new QTreeWidgetItem(root, {"Size", QString("%1 bytes").arg(fileInfo.size)});
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
    tree->setHeaderLabels({"Field", "Value"});

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
