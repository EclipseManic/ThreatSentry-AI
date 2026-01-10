# gui/__init__.py
"""
GUI Module - Threat Sentric AI Dashboard

Main exports:
- start_gui: Launch the dashboard application
- DashboardWindow: Main dashboard window

Enhanced features:
- enhanced_dashboard: Advanced analytics and visualization
- utils: Theme management and helper functions
"""

# Core utilities that don't depend on PyQt5
from .utils import ThemeManager, RiskHelper

# GUI components (lazy import to avoid PyQt5 dependency issues)
def __getattr__(name):
    if name in ['start_gui', 'DashboardWindow']:
        from .app import start_gui, DashboardWindow
        return locals()[name]
    elif name in ['AnalyticsEngine', 'AdvancedFilterPanel', 'AnalyticsPanel', 
                   'ExportManager', 'ModelStatusWidget', 'RemediationSuggestionsWidget']:
        from .enhanced_dashboard import (
            AnalyticsEngine, AdvancedFilterPanel, AnalyticsPanel,
            ExportManager, ModelStatusWidget, RemediationSuggestionsWidget
        )
        return locals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "start_gui",
    "DashboardWindow",
    "ThemeManager",
    "RiskHelper",
    "AnalyticsEngine",
    "AdvancedFilterPanel",
    "AnalyticsPanel",
    "ExportManager",
    "ModelStatusWidget",
    "RemediationSuggestionsWidget"
]
