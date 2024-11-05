# src/ui/styles.py

GLOBAL_STYLE = """
QMainWindow {
    background-color: #f0f0f0;
}
QPushButton {
    background-color: #0078d7;
    color: white;
    border: none;
    padding: 6px 12px;
    border-radius: 4px;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #1984e0;
}
QPushButton:pressed {
    background-color: #006cc1;
}
QLineEdit {
    padding: 5px;
    border: 1px solid #ccc;
    border-radius: 3px;
    background-color: white;
}
QGroupBox {
    font-weight: bold;
    border: 1px solid #ccc;
    border-radius: 5px;
    margin-top: 10px;
    padding-top: 10px;
}
QTableWidget {
    border: 1px solid #ccc;
    background-color: white;
    gridline-color: #f0f0f0;
}
QHeaderView::section {
    background-color: #f8f8f8;
    padding: 5px;
    border: 1px solid #ccc;
    font-weight: bold;
}
QTabWidget::pane {
    border: 1px solid #ccc;
    background: white;
}
QTabBar::tab {
    background: #f0f0f0;
    border: 1px solid #ccc;
    padding: 5px 10px;
}
QTabBar::tab:selected {
    background: white;
    border-bottom: 2px solid #0078d7;
}
"""
