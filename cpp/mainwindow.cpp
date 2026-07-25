#include "mainwindow.h"

#include "filefish/src/bridge.cxx.h"
#include "rust/cxx.h"

#include <QAction>
#include <QApplication>
#include <QColor>
#include <QFileDialog>
#include <QFont>
#include <QKeySequence>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTextBlock>
#include <QTextCursor>
#include <QTreeWidget>

#include <algorithm>
#include <functional>
#include <vector>

namespace
{

constexpr int BYTES_PER_LINE = 16;
constexpr int HEX_START = 10;                            // "00000000  " prefix
constexpr int HEX_CHARS_PER_BYTE = 3;                     // "xx "
constexpr int ASCII_START = HEX_START + BYTES_PER_LINE * HEX_CHARS_PER_BYTE + 1; // one space separates hex from ascii

// A QPlainTextEdit that knows the fixed hex-dump layout produced by
// dissect::hex_dump, so it can map mouse clicks back to byte offsets and
// highlight byte ranges in both the hex and ascii columns.
class HexDataView : public QPlainTextEdit
{
public:
    explicit HexDataView(QWidget *parent = nullptr) : QPlainTextEdit(parent) {}

    std::function<void(quint64)> onByteClicked;

    void highlightRange(quint64 start, quint64 end)
    {
        QList<QTextEdit::ExtraSelection> selections;
        if (end > start) {
            const QColor color(100, 150, 240, 120);

            const quint64 firstLine = start / BYTES_PER_LINE;
            const quint64 lastLine = (end - 1) / BYTES_PER_LINE;

            for (quint64 line = firstLine; line <= lastLine; ++line) {
                QTextBlock block = document()->findBlockByNumber(static_cast<int>(line));
                if (!block.isValid()) {
                    continue;
                }

                const quint64 lineStart = line * BYTES_PER_LINE;
                const int startByte = static_cast<int>(std::max(start, lineStart) - lineStart);
                const int endByte = static_cast<int>(std::min(end, lineStart + BYTES_PER_LINE) - lineStart);
                const int blockLen = block.length() - 1; // exclude the paragraph separator

                selections.append(makeSelection(block, blockLen, HEX_START + startByte * HEX_CHARS_PER_BYTE,
                                                 HEX_START + endByte * HEX_CHARS_PER_BYTE - 1, color));
                selections.append(makeSelection(block, blockLen, ASCII_START + startByte,
                                                 ASCII_START + endByte, color));
            }
        }
        setExtraSelections(selections);
    }

protected:
    void mousePressEvent(QMouseEvent *event) override
    {
        QPlainTextEdit::mousePressEvent(event);

        if (!onByteClicked) {
            return;
        }

        const QTextCursor cursor = cursorForPosition(event->pos());
        const int line = cursor.blockNumber();
        const int col = cursor.positionInBlock();

        int byteIndex = -1;
        if (col >= HEX_START && col < ASCII_START) {
            byteIndex = (col - HEX_START) / HEX_CHARS_PER_BYTE;
        } else if (col >= ASCII_START && col < ASCII_START + BYTES_PER_LINE) {
            byteIndex = col - ASCII_START;
        }

        if (byteIndex >= 0) {
            onByteClicked(static_cast<quint64>(line) * BYTES_PER_LINE + byteIndex);
        }
    }

private:
    static QTextEdit::ExtraSelection makeSelection(const QTextBlock &block, int blockLen, int fromCol, int toCol,
                                                     const QColor &color)
    {
        fromCol = std::clamp(fromCol, 0, blockLen);
        toCol = std::clamp(toCol, 0, blockLen);

        QTextCursor cursor(block);
        cursor.setPosition(block.position() + fromCol);
        cursor.setPosition(block.position() + toCol, QTextCursor::KeepAnchor);

        QTextEdit::ExtraSelection selection;
        selection.cursor = cursor;
        selection.format.setBackground(color);
        return selection;
    }
};

// Tracks the blocks/tree items for the currently loaded file, so tree
// selection and hex-view clicks can stay in sync with each other.
struct FileView
{
    rust::Vec<FfiBlock> blocks;
    std::vector<QTreeWidgetItem *> items;

    // Finds the most deeply nested block that contains `offset`, i.e. the
    // leaf that a click in the hex/ascii pane should resolve to.
    int leafForOffset(quint64 offset) const
    {
        int current = -1;
        bool found = true;
        while (found) {
            found = false;
            for (size_t i = 0; i < blocks.size(); ++i) {
                const auto &block = blocks[i];
                if (block.parent == current && offset >= block.start && offset < block.end) {
                    current = static_cast<int>(i);
                    found = true;
                    break;
                }
            }
        }
        return current;
    }
};

void loadFile(const QString &path, QTreeWidget *tree, HexDataView *dataView, FileView &fileView)
{
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

    fileView.blocks = std::move(fileInfo.blocks);
    fileView.items.assign(fileView.blocks.size(), nullptr);

    for (size_t i = 0; i < fileView.blocks.size(); ++i) {
        const auto &block = fileView.blocks[i];
        QTreeWidgetItem *parent = block.parent >= 0 ? fileView.items[block.parent] : tree->invisibleRootItem();
        auto *item = new QTreeWidgetItem(parent, {QString::fromStdString(std::string(block.label))});
        item->setData(0, Qt::UserRole, static_cast<quint64>(block.start));
        item->setData(0, Qt::UserRole + 1, static_cast<quint64>(block.end));
        if (!block.expandable) {
            item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
        } else if (block.default_expanded) {
            item->setExpanded(true);
        }
        fileView.items[i] = item;
    }

    dataView->setPlainText(QString::fromStdString(std::string(fileInfo.hex_dump)));
    dataView->highlightRange(0, 0);
}

void openFile(QWidget *parent, QTreeWidget *tree, HexDataView *dataView, FileView &fileView)
{
    const QString path = QFileDialog::getOpenFileName(parent, "Open File");
    loadFile(path, tree, dataView, fileView);
}

} // namespace

int run_app(rust::Vec<rust::String> args)
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

    auto *dataView = new HexDataView(splitter);
    dataView->setReadOnly(true);
    dataView->setPlaceholderText("Data view");
    dataView->setFont(QFont("monospace"));

    splitter->addWidget(tree);
    splitter->addWidget(dataView);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 2);

    window.setCentralWidget(splitter);

    FileView fileView;

    QObject::connect(tree, &QTreeWidget::currentItemChanged, &window, [dataView](QTreeWidgetItem *current, QTreeWidgetItem *) {
        if (!current) {
            dataView->highlightRange(0, 0);
            return;
        }
        const quint64 start = current->data(0, Qt::UserRole).toULongLong();
        const quint64 end = current->data(0, Qt::UserRole + 1).toULongLong();
        dataView->highlightRange(start, end);
    });

    dataView->onByteClicked = [tree, dataView, &fileView](quint64 offset) {
        const int leaf = fileView.leafForOffset(offset);
        if (leaf < 0) {
            return;
        }

        for (int ancestor = fileView.blocks[leaf].parent; ancestor >= 0; ancestor = fileView.blocks[ancestor].parent) {
            tree->expandItem(fileView.items[ancestor]);
        }

        QTreeWidgetItem *item = fileView.items[leaf];
        tree->setCurrentItem(item);
        tree->scrollToItem(item);

        const auto &block = fileView.blocks[leaf];
        dataView->highlightRange(block.start, block.end);
    };

    QMenu *fileMenu = window.menuBar()->addMenu("&File");
    QAction *openAction = fileMenu->addAction("&Open...");
    openAction->setShortcut(QKeySequence::Open);
    QObject::connect(openAction, &QAction::triggered, &window, [&window, tree, dataView, &fileView]() {
        openFile(&window, tree, dataView, fileView);
    });

    window.show();

    if (!args.empty()) {
        loadFile(QString::fromStdString(std::string(args[0])), tree, dataView, fileView);
    }

    return app.exec();
}
