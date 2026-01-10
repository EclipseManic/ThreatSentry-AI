"""
GUI Utilities Module

Common utilities and helpers for the GUI
"""


class ThemeManager:
    """Manage application themes - Light and Dark"""
    
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
            color: #e0e0e0;
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
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 4px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background-color: #2d2d2d;
            color: #e0e0e0;
            selection-background-color: #0078d4;
        }
        QSpinBox::up-button, QSpinBox::down-button {
            background-color: #3d3d3d;
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
        QCheckBox {
            color: #e0e0e0;
        }
        QCheckBox::indicator {
            background-color: #2d2d2d;
            border: 1px solid #555555;
        }
        QSlider::groove:horizontal {
            background-color: #3d3d3d;
        }
        QSlider::handle:horizontal {
            background-color: #0078d4;
        }
    """
    
    @staticmethod
    def apply_light_theme(app):
        """Apply light theme to application"""
        app.setStyle('Fusion')
        app.setStyleSheet(ThemeManager.LIGHT_THEME)
    
    @staticmethod
    def apply_dark_theme(app):
        """Apply dark theme to application"""
        app.setStyle('Fusion')
        app.setStyleSheet(ThemeManager.DARK_THEME)


class RiskHelper:
    """Helper functions for risk-related operations"""
    
    RISK_LABELS = {0: "Low", 1: "Medium", 2: "High"}
    RISK_COLORS = {
        "Low": "#44aa44",
        "Medium": "#ffaa44",
        "High": "#ff4444"
    }
    
    @staticmethod
    def get_risk_text(risk_label) -> str:
        """Convert risk label to text"""
        return RiskHelper.RISK_LABELS.get(risk_label, "Unknown")
    
    @staticmethod
    def get_risk_color(risk_text: str) -> str:
        """Get color for risk level"""
        return RiskHelper.RISK_COLORS.get(risk_text, "#888888")
    
    @staticmethod
    def risk_to_numeric(risk_label) -> float:
        """Convert risk label to numeric value"""
        if risk_label is None:
            return 0.0
        if risk_label == 2 or "high" in str(risk_label).lower():
            return 2.0
        elif risk_label == 1 or "medium" in str(risk_label).lower():
            return 1.0
        else:
            return 0.0
