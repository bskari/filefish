#include "mainwindow.h"

#include "filefish/src/bridge.cxx.h"
#include "rust/cxx.h"

#include <QAbstractScrollArea>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QColor>
#include <QFileDialog>
#include <QFont>
#include <QFontMetrics>
#include <QKeySequence>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QSplitter>
#include <QTreeWidget>

#include <algorithm>
#include <functional>
#include <vector>

namespace
{

constexpr int BYTES_PER_LINE = 16;
constexpr int HEX_START = 10;                                                    // "00000000  " prefix
constexpr int HEX_CHARS_PER_BYTE = 3;                                            // "xx "
constexpr int ASCII_START = HEX_START + BYTES_PER_LINE * HEX_CHARS_PER_BYTE + 1; // one space separates hex from ascii

// A QAbstractScrollArea that renders only the visible lines of a hex dump on
// demand, so opening large files doesn't stall building a document up front.
class HexDataView : public QAbstractScrollArea
{
public:
    explicit HexDataView(QWidget *parent = nullptr) : QAbstractScrollArea(parent)
    {
        setFont(QFont("monospace"));
        verticalScrollBar()->setSingleStep(1);
    }

    std::function<void(quint64)> onByteClicked;

    void setData(rust::Vec<uint8_t> data)
    {
        m_data = QByteArray(reinterpret_cast<const char *>(data.data()), static_cast<qsizetype>(data.size()));
        verticalScrollBar()->setValue(0);
        updateScrollBars();
        viewport()->update();
    }

    void highlightRange(quint64 start, quint64 end)
    {
        m_hlStart = start;
        m_hlEnd = end;
        viewport()->update();
    }

    // Scrolls so the line containing `start` is visible, but only if it isn't
    // already on screen.
    void scrollToRangeIfNeeded(quint64 start)
    {
        const int targetLine = static_cast<int>(start / BYTES_PER_LINE);
        const int firstVisible = verticalScrollBar()->value();
        const int vis = visibleLineCount();
        if (targetLine >= firstVisible && targetLine < firstVisible + vis) {
            return;
        }
        verticalScrollBar()->setValue(targetLine - vis / 2);
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter painter(viewport());
        painter.setFont(font());

        const QFontMetrics fm(font());
        const int lineH = fm.height();
        const int ascent = fm.ascent();

        const int firstLine = verticalScrollBar()->value();
        const int lastLine = std::min(firstLine + visibleLineCount() + 1, lineCount());

        for (int line = firstLine; line < lastLine; ++line) {
            const int y = (line - firstLine) * lineH;

            const quint64 byteStart = static_cast<quint64>(line) * BYTES_PER_LINE;
            const quint64 byteEnd = std::min(byteStart + BYTES_PER_LINE, static_cast<quint64>(m_data.size()));
            const int nBytes = static_cast<int>(byteEnd - byteStart);

            // Build the line text first so we can measure exact pixel positions.
            QString text;
            text.reserve(ASCII_START + BYTES_PER_LINE + 2);
            text = QString::asprintf("%08llx  ", static_cast<unsigned long long>(byteStart));
            for (int i = 0; i < nBytes; ++i) {
                text += QString::asprintf("%02x ", static_cast<uint8_t>(m_data[static_cast<qsizetype>(byteStart) + i]));
            }
            for (int i = nBytes; i < BYTES_PER_LINE; ++i) {
                text += "   ";
            }
            text += ' ';
            for (int i = 0; i < nBytes; ++i) {
                const uint8_t b = static_cast<uint8_t>(m_data[static_cast<qsizetype>(byteStart) + i]);
                text += (b >= 0x20 && b < 0x7f) ? QChar(b) : QChar('.');
            }

            // Draw highlight backgrounds using fm.horizontalAdvance to get pixel
            // positions that exactly match what drawText renders, avoiding any
            // per-character width drift from col * charW approximations.
            if (m_hlEnd > m_hlStart) {
                const quint64 lineHlStart = std::max(m_hlStart, byteStart);
                const quint64 lineHlEnd = std::min(m_hlEnd, byteEnd);
                if (lineHlStart < lineHlEnd) {
                    const QColor color(100, 150, 240, 120);
                    const int sb = static_cast<int>(lineHlStart - byteStart);
                    const int eb = static_cast<int>(lineHlEnd - byteStart);

                    const int xHexS = fm.horizontalAdvance(text.left(HEX_START + sb * HEX_CHARS_PER_BYTE));
                    const int xHexE = fm.horizontalAdvance(text.left(HEX_START + eb * HEX_CHARS_PER_BYTE - 1));
                    const int xAscS = fm.horizontalAdvance(text.left(ASCII_START + sb));
                    const int xAscE = fm.horizontalAdvance(text.left(ASCII_START + eb));

                    painter.fillRect(xHexS, y, xHexE - xHexS, lineH, color);
                    painter.fillRect(xAscS, y, xAscE - xAscS, lineH, color);
                }
            }

            painter.drawText(0, y + ascent, text);
        }
    }

    void resizeEvent(QResizeEvent *event) override
    {
        QAbstractScrollArea::resizeEvent(event);
        updateScrollBars();
    }

    void scrollContentsBy(int, int) override
    {
        viewport()->update();
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (!onByteClicked) {
            return;
        }

        const QFontMetrics fm(font());
        const int charW = fm.horizontalAdvance(QChar('0'));
        const int lineH = fm.height();

        const int line = verticalScrollBar()->value() + event->pos().y() / lineH;
        const int col = event->pos().x() / charW;

        int byteIndex = -1;
        if (col >= HEX_START && col < ASCII_START) {
            byteIndex = (col - HEX_START) / HEX_CHARS_PER_BYTE;
        } else if (col >= ASCII_START && col < ASCII_START + BYTES_PER_LINE) {
            byteIndex = col - ASCII_START;
        }

        if (byteIndex >= 0 && byteIndex < BYTES_PER_LINE) {
            const quint64 offset = static_cast<quint64>(line) * BYTES_PER_LINE + static_cast<quint64>(byteIndex);
            if (offset < static_cast<quint64>(m_data.size())) {
                onByteClicked(offset);
            }
        }
    }

private:
    QByteArray m_data;
    quint64 m_hlStart = 0;
    quint64 m_hlEnd = 0;

    int lineCount() const
    {
        return static_cast<int>((m_data.size() + BYTES_PER_LINE - 1) / BYTES_PER_LINE);
    }

    int visibleLineCount() const
    {
        const QFontMetrics fm(font());
        return viewport()->height() / fm.height();
    }

    void updateScrollBars()
    {
        const int total = lineCount();
        const int visible = visibleLineCount();
        verticalScrollBar()->setRange(0, std::max(0, total - visible));
        verticalScrollBar()->setPageStep(visible);
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

    dataView->setData(std::move(fileInfo.data));
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
        dataView->scrollToRangeIfNeeded(start);
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
