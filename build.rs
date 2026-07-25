fn main() {
    // Force Qt6, since both Qt5 and Qt6 dev packages are installed and
    // `qmake` on PATH defaults to Qt5.
    unsafe {
        std::env::set_var("QT_VERSION_MAJOR", "6");
    }

    cxx_qt_build::CxxQtBuilder::new()
        .qt_module("Widgets")
        .qt_module("Gui")
        .file("src/bridge.rs")
        .cc_builder(|cc| {
            cc.file("cpp/mainwindow.cpp");
            cc.include("cpp");
        })
        .build();
}
