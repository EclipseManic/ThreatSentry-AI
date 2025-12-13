"""
Theme Manager for Threat Sentric AI Dashboard

Provides light and dark theme options with professional styling
"""

from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import QApplication


class ThemeManager:
    """Manage application themes"""
    
    LIGHT_THEME = """
        QMainWindow, QWidget {
            background-color: #ffffff;
            color: #333333;
        }
        QTableView {
            background-color: #ffffff;
            alternate-background-color: #f5f5f5;
            gridline-color: #dddddd;
            color: #333333;
        }
        QTableView::item {
            padding: 4px;
        }
        QHeaderView::section {
            background-color: #f0f0f0;
            color: #333333;
            padding: 5px;
            border: 1px solid #dddddd;
        }
        QPushButton {
            background-color: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #0052a3;
        }
        QPushButton:pressed {
            background-color: #003d7a;
        }
        QComboBox, QSpinBox, QLineEdit {
            background-color: #ffffff;
            color: #333333;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 4px;
        }
        QTabWidget::pane {
            border: 1px solid #cccccc;
        }
        QTabBar::tab {
            background-color: #f0f0f0;
            color: #333333;
            padding: 6px 20px;
            border: 1px solid #cccccc;
            border-bottom: none;
        }
        QTabBar::tab:selected {
            background-color: #0066cc;
            color: white;
        }
        QLabel {
            color: #333333;
        }
    """
    
    DARK_THEME = """
        QMainWindow, QWidget {
            background-color: #1e1e1e;
            color: #e0e0e0;
        }
        QTableView {
            background-color: #2d2d2d;
            alternate-background-color: #1a1a1a;
            gridline-color: #444444;
            color: #e0e0e0;
        }
        QTableView::item {
            padding: 4px;
        }
        QHeaderView::section {
            background-color: #3d3d3d;
            color: #e0e0e0;
            padding: 5px;
            border: 1px solid #444444;
        }
        QPushButton {
            background-color: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #005a9e;
        }
        QPushButton:pressed {
            background-color: #003d6b;
        }
        QComboBox, QSpinBox, QLineEdit {
            background-color: #2d2d2d;
            color: #e0e0e0;
            border: 1px solid #444444;
            border-radius: 4px;
            padding: 4px;
        }
        QTabWidget::pane {
            border: 1px solid #444444;
        }
        QTabBar::tab {
            background-color: #3d3d3d;
            color: #e0e0e0;
            padding: 6px 20px;
            border: 1px solid #444444;
            border-bottom: none;
        }
        QTabBar::tab:selected {
            background-color: #0078d4;
            color: white;
        }
        QLabel {
            color: #e0e0e0;
        }
        QMessageBox {
            background-color: #1e1e1e;
        }
        QMessageBox QLabel {
            color: #e0e0e0;
        }
    """
    
    @staticmethod
    def apply_light_theme(app: QApplication):
        """Apply light theme to application"""
        app.setStyle('Fusion')
        app.setStyleSheet(ThemeManager.LIGHT_THEME)
    
    @staticmethod
    def apply_dark_theme(app: QApplication):
        """Apply dark theme to application"""
        app.setStyle('Fusion')
        app.setStyleSheet(ThemeManager.DARK_THEME)
