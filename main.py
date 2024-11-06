# main.py

import sys
import logging
from PyQt5 import QtWidgets
from ui.main_window import MainWindow
from utils.logging_config import setup_logging

def main():
    setup_logging()
    logging.info("Anwendung gestartet")
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
