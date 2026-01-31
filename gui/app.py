"""
GUI application (PyQt5)

This module contains the main dashboard window used to view device records,
manually trigger scans, upload device lists, and send alerts. The GUI is
designed to be defensive so it continues to operate even if optional modules
such as the training orchestrator are missing.
"""

import sys
import pandas as pd
import threading
from concurrent.futures import ThreadPoolExecutor

# Ensure UTF-8 encoding for console output (fixes font corruption on Windows)
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableView, QMessageBox, QHeaderView, QFileDialog, QComboBox, QSpinBox,
    QCheckBox, QTextBrowser, QDialog, QLineEdit, QSizePolicy, QTabWidget, QStyledItemDelegate,
    QProgressBar
)
from PyQt5.QtCore import QTimer, Qt, QAbstractTableModel, QSortFilterProxyModel, QThread, pyqtSignal, QModelIndex
from PyQt5.QtGui import QColor, QFont
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from data import get_session, Device, init_db
from alerts import send_email_alert, build_device_summary
from collectors import shodan_collector, nvd_collector
from core import get_logger
from core.config import SHODAN_QUERIES, SHODAN_QUERY
import importlib
import ipaddress

# Import enhanced dashboard components
try:
    from .enhanced_dashboard import (
        AdvancedFilterPanel, AnalyticsPanel, ExportManager,
        ModelStatusWidget
    )
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError as e:
    ENHANCED_FEATURES_AVAILABLE = False
    logger = get_logger("gui")
    logger.warning("Enhanced dashboard features not available: %s", e)

# Import theme manager
try:
    from .utils import ThemeManager
    THEME_MANAGER_AVAILABLE = True
except ImportError as e:
    THEME_MANAGER_AVAILABLE = False

logger = get_logger("gui")

# Thread pool for network I/O operations in GUI (scans, enrichment)
_network_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="gui_network_io")


class PandasModel(QAbstractTableModel):
    def __init__(self, df=pd.DataFrame()):
        super().__init__()
        self._df = df.copy()

    def setDataFrame(self, df: pd.DataFrame):
        rename_map = {
            'ip': 'IP', 'org': 'Org', 'country': 'Country', 'open_ports': 'Open Ports',
            'cve_count': 'CVE Count', 'max_cvss': 'Max CVSS', 'risk': 'Risk', 'last_seen': 'Last Seen'
        }
        df = df.copy()
        df.columns = [rename_map.get(c, c) for c in df.columns]
        self.beginResetModel()
        self._df = df
        self.endResetModel()

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            try:
                return str(self._df.columns[section])
            except Exception:
                return ''
        else:
            return str(section)

    def rowCount(self, parent=None):
        return len(self._df.index)

    def columnCount(self, parent=None):
        return len(self._df.columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        value = self._df.iloc[index.row(), index.column()]
        if role == Qt.DisplayRole:
            return str(value)
        if role == Qt.TextColorRole:
            # Always use bright white text for visibility in dark theme
            return QColor('#ffffff')
        if role == Qt.TextAlignmentRole:
            col_name = self._df.columns[index.column()]
            if col_name in ('S.No', 'Open Ports', 'CVE Count', 'Max CVSS'):
                return Qt.AlignCenter
            if col_name == 'IP':
                return Qt.AlignLeft | Qt.AlignVCenter
            return Qt.AlignCenter
        # Note: BackgroundRole is now handled by RiskColorDelegate for the Risk column
        # This removes per-cell color computation and improves rendering performance
        return None


class PaginatedPandasModel(QAbstractTableModel):
    """Paginated table model that displays data in chunks to improve performance with large datasets.
    
    Shows ROWS_PER_PAGE rows at a time, with ability to load more via pagination control.
    """
    ROWS_PER_PAGE = 50  # Show 50 rows initially, then 50 more per "Load More" click
    
    def __init__(self, df=pd.DataFrame()):
        super().__init__()
        self._full_df = df.copy()
        self._displayed_rows = self.ROWS_PER_PAGE
        self._df = self._full_df.iloc[:self._displayed_rows].copy() if len(self._full_df) > 0 else pd.DataFrame()

    def setDataFrame(self, df: pd.DataFrame):
        """Set the full dataset and reset pagination to first page"""
        rename_map = {
            'ip': 'IP', 'org': 'Org', 'country': 'Country', 'open_ports': 'Open Ports',
            'cve_count': 'CVE Count', 'max_cvss': 'Max CVSS', 'risk': 'Risk', 'last_seen': 'Last Seen'
        }
        df = df.copy()
        df.columns = [rename_map.get(c, c) for c in df.columns]
        self.beginResetModel()
        self._full_df = df
        self._displayed_rows = min(self.ROWS_PER_PAGE, len(self._full_df))
        self._df = self._full_df.iloc[:self._displayed_rows].copy() if len(self._full_df) > 0 else pd.DataFrame()
        self.endResetModel()
    
    def load_more(self) -> bool:
        """Load next page of results. Returns True if more rows available after loading."""
        if self._displayed_rows >= len(self._full_df):
            return False
        
        old_count = self._displayed_rows
        self._displayed_rows = min(self._displayed_rows + self.ROWS_PER_PAGE, len(self._full_df))
        
        # Notify view of new rows being inserted (use QModelIndex() for root index)
        self.beginInsertRows(QModelIndex(), old_count, self._displayed_rows - 1)
        self._df = self._full_df.iloc[:self._displayed_rows].copy()
        self.endInsertRows()
        
        return self._displayed_rows < len(self._full_df)
    
    def get_total_rows(self) -> int:
        """Total number of rows in dataset"""
        return len(self._full_df)
    
    def get_displayed_rows(self) -> int:
        """Number of rows currently displayed"""
        return self._displayed_rows

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            try:
                return str(self._df.columns[section])
            except Exception:
                return ''
        else:
            return str(section)

    def rowCount(self, parent=None):
        return len(self._df.index)

    def columnCount(self, parent=None):
        return len(self._df.columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        value = self._df.iloc[index.row(), index.column()]
        if role == Qt.DisplayRole:
            return str(value)
        if role == Qt.TextColorRole:
            return QColor('#ffffff')
        if role == Qt.TextAlignmentRole:
            col_name = self._df.columns[index.column()]
            if col_name in ('S.No', 'Open Ports', 'CVE Count', 'Max CVSS'):
                return Qt.AlignCenter
            if col_name == 'IP':
                return Qt.AlignLeft | Qt.AlignVCenter
            return Qt.AlignCenter
        return None


class DeviceFetchWorker(QThread):
    """Worker thread for fetching device data without blocking the UI"""
    finished = pyqtSignal()  # Emitted when fetch is complete
    result = pyqtSignal(pd.DataFrame)  # Emitted with the fetched DataFrame
    error = pyqtSignal(str)  # Emitted if an error occurs
    
    def __init__(self, use_cache=True):
        super().__init__()
        self.use_cache = use_cache
        self.cached_df = None
        self.last_device_count = 0
    
    def run(self):
        """Run the fetch operation in a worker thread"""
        try:
            session = get_session()
            current_count = session.query(Device).count()
            session.close()
            
            # Check if cache is still valid (same device count)
            if self.use_cache and self.cached_df is not None and current_count == self.last_device_count:
                logger.debug("Worker: Using cached device DataFrame (count: %d)", current_count)
                self.result.emit(self.cached_df)
                self.finished.emit()
                return
            
            # Cache miss - fetch fresh data
            logger.debug("Worker: Fetching fresh device data from database (count: %d)", current_count)
            session = get_session()
            devices = session.query(Device).all()
            rows = []
            for d in devices:
                risk_text = {0: "Low", 1: "Medium", 2: "High"}.get(d.risk_label, "Unknown")
                rows.append({
                    "ip": d.ip,
                    "org": d.org or "",
                    "country": d.country or "",
                    "open_ports": d.num_open_ports or 0,
                    "cve_count": d.cve_count or 0,
                    "max_cvss": d.max_cvss or 0.0,
                    "risk": risk_text,
                    "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M:%S") if d.last_seen else ""
                })
            session.close()
            
            # Update cache
            df = pd.DataFrame(rows)
            self.cached_df = df
            self.last_device_count = current_count
            self.result.emit(df)
            self.finished.emit()
        except Exception as e:
            logger.error("Worker: Error fetching devices: %s", str(e))
            self.error.emit(str(e))
            self.finished.emit()


class RiskColorDelegate(QStyledItemDelegate):
    """Custom delegate for Risk column to optimize color rendering with caching"""
    
    # Cache risk level to color mapping (computed once, reused for all cells)
    RISK_COLORS = {
        'high': QColor('#8b3a3a'),      # Dark red
        'medium': QColor('#8b6f3f'),    # Dark orange
        'low': QColor('#3a5f8b'),       # Dark blue
    }
    DEFAULT_COLOR = QColor('#3a3a3a')   # Default gray
    TEXT_COLOR = QColor('#ffffff')      # White text
    
    def paint(self, painter, option, index):
        """Override paint to efficiently apply background colors"""
        if not index.isValid():
            super().paint(painter, option, index)
            return
        
        # Get the risk value from the model
        try:
            risk_value = index.data(Qt.DisplayRole)
            if risk_value:
                risk_lower = str(risk_value).lower()
                # Get cached color for this risk level
                bg_color = self.RISK_COLORS.get(risk_lower, self.DEFAULT_COLOR)
            else:
                bg_color = self.DEFAULT_COLOR
        except Exception:
            bg_color = self.DEFAULT_COLOR
        
        # Draw background with cached color
        painter.fillRect(option.rect, bg_color)
        
        # Draw text with white color
        painter.setPen(self.TEXT_COLOR)
        painter.drawText(option.rect, Qt.AlignCenter, str(risk_value))


class DashboardWindow(QWidget):
    # Signals for thread-safe communication from background threads to main thread
    scan_completed = pyqtSignal(list)  # Emits list of error messages (empty if no errors)
    training_completed = pyqtSignal(str, bool)  # Emits (message, is_success)
    
    def __init__(self, refresh_interval_ms=60000):
        super().__init__()
        self.setWindowTitle('Threat Sentric AI - Dashboard')
        self.layout = QVBoxLayout(self)
        
        # Cache for devices data
        self.cached_df = None
        self.last_device_count = 0
        self.cache_timestamp = None
        
        # Worker thread for fetching devices
        self.fetch_worker = None
        self.is_fetching = False
        
        # Connect signals to handlers for thread-safe updates
        self.scan_completed.connect(self._on_scan_completed)
        self.training_completed.connect(self._on_training_completed)

        # Header: left (scan/refresh/query/presets), center (title), right (actions + alert controls)
        header_top = QHBoxLayout()
        header_top.setContentsMargins(6, 6, 6, 6)
        header_top.setSpacing(10)
        left_group = QHBoxLayout()

        # Scan and Refresh on left (Scan on top, search below)
        left_col = QVBoxLayout()
        scan_row = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Now")
        self.scan_btn.setFixedWidth(80)
        self.scan_btn.clicked.connect(self.scan_now)
        scan_row.addWidget(self.scan_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedWidth(80)
        self.refresh_btn.clicked.connect(self.refresh)
        scan_row.addWidget(self.refresh_btn)

        left_col.addLayout(scan_row)

        # Search input sits below Scan/Refresh (linear)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText('Search IP / Org / Country / Risk (auto-detect)')
        self.search_input.setFixedWidth(300)
        # debounce typing to avoid heavy filtering on each keystroke
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(300)  # ms
        self._pending_search_text = ''
        self._search_timer.timeout.connect(lambda: self.proxy.setFilterText(self._pending_search_text, ip_only=self._pending_search_text_is_ip if hasattr(self, '_pending_search_text_is_ip') else False))
        def _on_text_change_for_debounce(t):
            self._pending_search_text = t
            # detect ip approximately
            try:
                candidate = t.split(':', 1)[0].strip()
                ipaddress.ip_address(candidate)
                self._pending_search_text_is_ip = True
            except Exception:
                self._pending_search_text_is_ip = False
            self._search_timer.start()

        self.search_input.textChanged.connect(_on_text_change_for_debounce)
        left_col.addWidget(self.search_input)

        left_group.addLayout(left_col)

        # Shodan query input and preset selector placed in the same left column
        # so the search box stays directly under Scan/Refresh (linear layout).
        self._shodan_query = QLineEdit()
        self._shodan_query.setPlaceholderText('Shodan query (optional) — e.g. org:"Your Company" or port:3389')
        self._shodan_query.setToolTip('Enter an advanced Shodan query or leave empty to use the configured default')
        self._shodan_query.setFixedWidth(380)
        # Put Shodan controls into left_col so they appear below Scan/Refresh and Search in a single stacked column
        left_col.addWidget(self._shodan_query)

        try:
            preset_keys = list(SHODAN_QUERIES.keys())
        except Exception:
            preset_keys = []
        self._shodan_preset_keys = preset_keys
        self._shodan_preset = QComboBox()
        self._shodan_preset.addItem('Custom')
        for k in preset_keys:
            self._shodan_preset.addItem(k)
        self._shodan_preset.setFixedWidth(160)
        left_col.addWidget(self._shodan_preset)

        # Default the preset selector: prefer SHODAN_QUERY (if provided), else pick the
        # first preset key from SHODAN_QUERIES so the UI shows a sensible default.
        try:
            default_key = None
            if SHODAN_QUERY and str(SHODAN_QUERY).strip():
                # try to find a preset that matches the configured SHODAN_QUERY
                for k, v in (SHODAN_QUERIES or {}).items():
                    if v == SHODAN_QUERY:
                        default_key = k
                        break
            if default_key is None:
                # pick the first preset key if available
                keys = list(SHODAN_QUERIES.keys()) if SHODAN_QUERIES else []
                default_key = keys[0] if keys else None

            if default_key and default_key in self._shodan_preset_keys:
                idx = self._shodan_preset_keys.index(default_key) + 1  # +1 for 'Custom' entry
                self._shodan_preset.setCurrentIndex(idx)
        except Exception:
            pass

        # When a preset is selected, populate the query box for clarity; 'Custom' clears it.
        def _on_preset_changed(i):
            try:
                if i <= 0:
                    self._shodan_query.clear()
                else:
                    key = self._shodan_preset_keys[i - 1]
                    q = SHODAN_QUERIES.get(key, '')
                    # show preset in the query box but keep it editable for quick changes
                    self._shodan_query.setText(q or '')
            except Exception:
                pass

        self._shodan_preset.currentIndexChanged.connect(_on_preset_changed)

        header_top.addLayout(left_group)
        header_top.addStretch(1)

        # Prepare alert controls (so they can be placed on right header)
        self._alert_cat = QComboBox()
        self._alert_cat.setToolTip("Category for manual alerts")
        self._alert_cat.setFixedWidth(220)
        self._alert_cat.addItems(["High: loading", "Medium: loading", "Low: loading", "All: loading"])

        self._alert_limit = QSpinBox()
        self._alert_limit.setRange(1, 1000)
        self._alert_limit.setValue(50)
        self._alert_limit.setFixedWidth(70)

        self._alert_mark = QCheckBox("Mark")
        self._alert_mark.setToolTip("Mark devices as notified after send")

        # Right group: actions + alert controls
        right_group = QHBoxLayout()
        self.actions_combo = QComboBox()
        # Refresh removed from actions (now a left-side button). Add Send Selected and keep Upload here.
        # "Train Model" removed so GUI can run even if the training script/module is deleted.
        self.actions_combo.addItems(["Send Filtered", "Send Selected", "Send All", "Upload"])
        self.actions_combo.setToolTip("Choose an action and click Go")
        self.actions_combo.setFixedWidth(160)
        right_group.addWidget(self.actions_combo)

        self.actions_go = QPushButton("Go")
        self.actions_go.setFixedWidth(60)
        self.actions_go.clicked.connect(lambda: self._perform_action(self.actions_combo.currentText()))
        right_group.addWidget(self.actions_go)

        # Add alert controls next to Actions so users can pick category/limit before sending
        right_group.addSpacing(8)
        right_group.addWidget(self._alert_cat)
        right_group.addWidget(self._alert_limit)
        right_group.addWidget(self._alert_mark)

        header_top.addLayout(right_group)
        self.layout.addLayout(header_top)

        self.title_label = QLabel("Threat Sentric AI - Threat Hunting Dashboard")
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont('Arial', 14, QFont.Bold)
        self.title_label.setFont(title_font)
        self.title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.layout.addWidget(self.title_label)

        self.table_view = QTableView()
        self.model = PaginatedPandasModel(pd.DataFrame())  # Use paginated model for large result sets
        # Use a proxy model so we can filter across multiple columns
        class MultiColumnFilterProxy(QSortFilterProxyModel):
            """Fast multi-column filter that works with paginated model by filtering the full dataset,
            then having the paginated model display the filtered results.
            """
            def __init__(self, parent=None, paginated_model=None):
                super().__init__(parent)
                self._filter_text = ''
                self._ip_only = False
                self._cols = []
                self._col_indices = []
                self._mask = None
                self._paginated_model = paginated_model

            def setSourceModel(self, model):
                super().setSourceModel(model)
                self._paginated_model = model
                try:
                    df_to_use = model._full_df if hasattr(model, '_full_df') else model._df
                    self._cols = list(df_to_use.columns)
                except Exception:
                    self._cols = []

            def setFilterText(self, text: str, ip_only: bool = False):
                t = (text or '').strip()
                self._filter_text = t.lower()
                self._ip_only = bool(ip_only)

                try:
                    src = self.sourceModel()
                    df_to_use = src._full_df if hasattr(src, '_full_df') else src._df
                    self._cols = list(df_to_use.columns) if hasattr(src, '_df') else []
                except Exception:
                    self._cols = []

                # choose columns to search
                if self._cols:
                    if self._ip_only and 'IP' in self._cols:
                        self._col_indices = [self._cols.index('IP')]
                    else:
                        preferred = ['IP', 'Org', 'Country', 'Risk', 'Service', 'Service Category', 'service_category']
                        self._col_indices = [self._cols.index(c) for c in preferred if c in self._cols]
                        if not self._col_indices:
                            self._col_indices = list(range(len(self._cols)))
                else:
                    self._col_indices = []

                # build a boolean mask on full dataset and filter the paginated model
                try:
                    src = self.sourceModel()
                    df = src._full_df if hasattr(src, '_full_df') else src._df
                    
                    if not self._filter_text:
                        # No filter - show full dataset
                        filtered_df = df.copy()
                    else:
                        ft = self._filter_text
                        masks = None
                        for ci in self._col_indices:
                            col = df.iloc[:, ci].astype(str).fillna('').str.lower()
                            m = col.str.contains(ft, regex=False)
                            masks = m if masks is None else (masks | m)
                        filtered_df = df[masks] if masks is not None else pd.DataFrame()
                    
                    # Update the paginated model with filtered results and reset pagination
                    if self._paginated_model:
                        self._paginated_model.setDataFrame(filtered_df)
                except Exception:
                    pass

        self.proxy = MultiColumnFilterProxy(self, self.model)
        self.proxy.setSourceModel(self.model)
        # Note: We don't use proxy as the table model anymore, we directly use the paginated model
        # because the proxy filters the underlying data in the paginated model
        self.table_view.setModel(self.model)  # Use paginated model directly

        
        # Set custom delegate for Risk column to optimize color rendering
        risk_delegate = RiskColorDelegate(self.table_view)
        # Find the Risk column index (it should be at a fixed position based on column order)
        try:
            risk_col_index = list(self.model._df.columns).index('Risk') if 'Risk' in self.model._df.columns else -1
            if risk_col_index >= 0:
                self.table_view.setItemDelegateForColumn(risk_col_index, risk_delegate)
                logger.debug("Risk color delegate applied to column %d", risk_col_index)
        except Exception as e:
            logger.warning("Could not apply Risk delegate: %s", e)
        
        self.table_view.setAlternatingRowColors(True)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_view.verticalHeader().setVisible(False)
        header_font = QFont('Arial', 10, QFont.Bold)
        self.table_view.horizontalHeader().setFont(header_font)
        self.table_view.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.table_view.horizontalHeader().setFixedHeight(36)
        self.table_view.setSortingEnabled(True)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setDefaultSectionSize(28)
        # Make selection operate on whole rows and allow multi-selection for Send Selected
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.setSelectionMode(QTableView.ExtendedSelection)
        
        # Create main tabs for Dashboard, Analytics, and Tools
        self.main_tabs = QTabWidget()
        
        # Dashboard Tab (main view with table + chart)
        dashboard_widget = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_widget)
        dashboard_layout.setContentsMargins(6, 6, 6, 6)
        dashboard_layout.setSpacing(10)
        
        # Add advanced filters if available - make them prominent at top
        self.advanced_filters = None
        if ENHANCED_FEATURES_AVAILABLE:
            try:
                self.advanced_filters = AdvancedFilterPanel()
                self.advanced_filters.filters_changed.connect(self.on_advanced_filters_changed)
                self.advanced_filters.setFixedHeight(50)
                dashboard_layout.addWidget(self.advanced_filters)
                logger.info("Advanced filters added to dashboard")
            except Exception as e:
                logger.warning("Could not add advanced filters: %s", e)
        
        # Create horizontal layout for table and chart (side-by-side)
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)
        
        # Table with pagination controls on the left (65% width)
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(6)
        
        self.table_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.table_view.setMinimumHeight(300)
        table_layout.addWidget(self.table_view, 1)
        
        # Pagination controls
        pagination_layout = QHBoxLayout()
        pagination_layout.setContentsMargins(0, 0, 0, 0)
        self.pagination_label = QLabel("Loading...")
        pagination_layout.addWidget(self.pagination_label, 1)
        self.load_more_btn = QPushButton("Load More (50 rows)")
        self.load_more_btn.setFixedWidth(180)
        self.load_more_btn.clicked.connect(self._on_load_more_clicked)
        self.load_more_btn.setVisible(False)  # Hidden until data loads
        pagination_layout.addWidget(self.load_more_btn)
        table_layout.addLayout(pagination_layout)
        
        content_layout.addWidget(table_container, 65)
        
        # Chart on the right (35% width)
        self.figure = Figure(figsize=(5, 4), facecolor='#2d2d2d', edgecolor='#444444')
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.canvas.setMinimumHeight(300)
        content_layout.addWidget(self.canvas, 35)
        
        dashboard_layout.addLayout(content_layout, 1)
        
        self.main_tabs.addTab(dashboard_widget, "Dashboard")
        
        # Analytics Tab (if enhanced features available) - lazy loaded on first click
        self.analytics_panel = None
        self.analytics_loaded = False
        self.model_status = None
        self.remediation_widget = None
        self.tools_widget = None
        self.tools_loaded = False
        
        if ENHANCED_FEATURES_AVAILABLE:
            # Create placeholder for Analytics tab (will be loaded on first access)
            analytics_placeholder = QWidget()
            analytics_placeholder_layout = QVBoxLayout(analytics_placeholder)
            analytics_placeholder_layout.addWidget(QLabel("Analytics will load when you click on this tab..."))
            analytics_placeholder_layout.addStretch()
            self.main_tabs.addTab(analytics_placeholder, "Analytics")
            
            # Create placeholder for Tools tab (will be loaded on first access)
            tools_placeholder = QWidget()
            tools_placeholder_layout = QVBoxLayout(tools_placeholder)
            tools_placeholder_layout.addWidget(QLabel("Tools will load when you click on this tab..."))
            tools_placeholder_layout.addStretch()
            self.main_tabs.addTab(tools_placeholder, "Tools")
            
            # Connect tab change signal to lazy load analytics/tools
            self.main_tabs.currentChanged.connect(self._on_tab_changed)
        
        # Add main tabs to layout
        self.layout.addWidget(self.main_tabs, 5)

        self.status_label = QLabel("")
        self.layout.addWidget(self.status_label)

        self.timer = QTimer()
        self.timer.setInterval(refresh_interval_ms)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

        self.refresh()
    
    def _on_tab_changed(self, tab_index):
        """Lazy load Analytics and Tools tabs when user switches to them"""
        if tab_index == 1 and not self.analytics_loaded and ENHANCED_FEATURES_AVAILABLE:
            # Analytics tab clicked (index 1)
            logger.debug("Lazy loading Analytics tab...")
            try:
                self.analytics_panel = AnalyticsPanel()
                self.main_tabs.widget(1).deleteLater()  # Remove placeholder
                self.main_tabs.insertTab(1, self.analytics_panel, "Analytics")
                self.analytics_loaded = True
                logger.info("Analytics tab loaded successfully")
            except Exception as e:
                logger.exception("Failed to load Analytics tab: %s", e)
                QMessageBox.warning(self, "Analytics", f"Failed to load analytics: {str(e)}")
        
        elif tab_index == 2 and not self.tools_loaded and ENHANCED_FEATURES_AVAILABLE:
            # Tools tab clicked (index 2)
            logger.debug("Lazy loading Tools tab...")
            try:
                tools_widget = QWidget()
                tools_layout = QVBoxLayout(tools_widget)
                
                # Model Status Section
                tools_layout.addWidget(QLabel("Model Training Status"))
                self.model_status = ModelStatusWidget()
                tools_layout.addWidget(self.model_status)
                
                tools_layout.addSpacing(20)
                
                # Export Section
                export_layout = QHBoxLayout()
                export_label = QLabel("Export Report:")
                export_layout.addWidget(export_label)
                
                export_csv_btn = QPushButton("Export to CSV")
                export_csv_btn.clicked.connect(self.export_to_csv)
                export_layout.addWidget(export_csv_btn)
                
                export_pdf_btn = QPushButton("Export to PDF")
                export_pdf_btn.clicked.connect(self.export_to_pdf)
                export_layout.addWidget(export_pdf_btn)
                
                export_layout.addStretch()
                tools_layout.addLayout(export_layout)
                
                tools_layout.addStretch()
                
                self.tools_widget = tools_widget
                self.main_tabs.widget(2).deleteLater()  # Remove placeholder
                self.main_tabs.insertTab(2, tools_widget, "Tools")
                self.tools_loaded = True
                logger.info("Tools tab loaded successfully")
            except Exception as e:
                logger.exception("Failed to load Tools tab: %s", e)
                QMessageBox.warning(self, "Tools", f"Failed to load tools: {str(e)}")
    
    def on_advanced_filters_changed(self, filters: dict):
        """Handle advanced filter changes - filter in-memory for instant response"""
        try:
            # Use cached data directly (no new fetch needed, cache is already loaded from refresh)
            if self.cached_df is None:
                logger.debug("No cached data available for filtering yet")
                return
            
            # Clear search when applying advanced filters
            self.search_input.blockSignals(True)
            self.search_input.clear()
            self.search_input.blockSignals(False)
            
            # Apply filters in-memory using raw column names (cached_df has lowercase names like 'max_cvss')
            df = self.cached_df.copy()
            
            # Check which columns exist (could be lowercase or capitalized depending on where data came from)
            max_cvss_col = 'Max CVSS' if 'Max CVSS' in df.columns else 'max_cvss' if 'max_cvss' in df.columns else None
            org_col = 'Org' if 'Org' in df.columns else 'org' if 'org' in df.columns else None
            country_col = 'Country' if 'Country' in df.columns else 'country' if 'country' in df.columns else None
            risk_col = 'Risk' if 'Risk' in df.columns else 'risk' if 'risk' in df.columns else None
            
            # Apply CVSS filters
            if max_cvss_col and filters.get('cvss_min') is not None:
                cvss_min = filters['cvss_min']
                # Convert to numeric to handle any string values
                df[max_cvss_col] = pd.to_numeric(df[max_cvss_col], errors='coerce')
                df = df[df[max_cvss_col] >= cvss_min]
                logger.debug("Applied CVSS min filter: %s", cvss_min)
            
            if max_cvss_col and filters.get('cvss_max') is not None:
                cvss_max = filters['cvss_max']
                # Convert to numeric to handle any string values
                df[max_cvss_col] = pd.to_numeric(df[max_cvss_col], errors='coerce')
                df = df[df[max_cvss_col] <= cvss_max]
                logger.debug("Applied CVSS max filter: %s", cvss_max)
            
            # Apply organization filter
            if org_col and filters.get('organization') and filters['organization'] != 'All Organizations':
                df = df[df[org_col] == filters['organization']]
                logger.debug("Applied organization filter: %s", filters['organization'])
            
            # Apply country filter
            if country_col and filters.get('country') and filters['country'] != 'All Countries':
                df = df[df[country_col] == filters['country']]
                logger.debug("Applied country filter: %s", filters['country'])
            
            # Apply risk filter
            if risk_col and filters.get('risk_level') and filters['risk_level'] != 'All Risks':
                df = df[df[risk_col] == filters['risk_level']]
                logger.debug("Applied risk filter: %s", filters['risk_level'])
            
            # Update table with filtered results (pagination resets automatically in setDataFrame)
            self.model.setDataFrame(df)
            self._update_pagination_controls()
            self.update_chart(df)
            self.status_label.setText(f"Filters applied | {len(df)} devices shown")
            logger.info("Filters applied: %s -> %d devices", filters, len(df))
        except Exception as e:
            logger.error("Error applying advanced filters: %s", e)
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
    
    def export_to_csv(self):
        """Export filtered devices to CSV"""
        if not ENHANCED_FEATURES_AVAILABLE:
            return
        
        filepath, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "", "CSV Files (*.csv)")
        if filepath:
            try:
                df = self.model._df
                devices_data = []
                
                for idx, row in df.iterrows():
                    devices_data.append({
                        'IP': row.get('IP', ''),
                        'Organization': row.get('Org', ''),
                        'Country': row.get('Country', ''),
                        'Open Ports': row.get('Open Ports', 0),
                        'CVE Count': row.get('CVE Count', 0),
                        'Max CVSS': row.get('Max CVSS', 0),
                        'Risk Level': row.get('Risk', ''),
                        'Last Seen': row.get('Last Seen', '')
                    })
                
                export_df = pd.DataFrame(devices_data)
                export_df.to_csv(filepath, index=False)
                QMessageBox.information(self, "Export Successful", f"Data exported to {filepath}")
                logger.info("Exported %d devices to CSV: %s", len(devices_data), filepath)
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Error exporting CSV: {str(e)}")
                logger.error("CSV export failed: %s", e)
    
    def export_to_pdf(self):
        """Export filtered devices to PDF report"""
        if not ENHANCED_FEATURES_AVAILABLE:
            return
        
        filepath, _ = QFileDialog.getSaveFileName(self, "Export to PDF", "", "PDF Files (*.pdf)")
        if filepath:
            try:
                session = get_session()
                devices = session.query(Device).all()
                session.close()
                
                success = ExportManager.export_to_pdf(devices, filepath)
                if success:
                    QMessageBox.information(self, "Export Successful", f"Report exported to {filepath}")
                else:
                    QMessageBox.critical(self, "Export Failed", "Failed to export PDF report")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Error exporting PDF: {str(e)}")
                logger.error("PDF export failed: %s", e)

    def _perform_action(self, act: str):
        if act == 'Refresh':
            self.refresh()
        elif act == 'Train Model':
            self.train_model()
        elif act == 'Send Filtered':
            self.send_filtered_alerts()
        elif act == 'Send Selected':
            # Ask the user for category/mark options before sending selected
            self._show_send_selected_dialog()
        elif act == 'Send All':
            self.send_all_alerts()
        elif act == 'Upload':
            self.upload_file()

    def _on_search_changed(self, text: str):
        """Auto-detect IP input and update proxy filter accordingly."""
        t = (text or '').strip()
        if not hasattr(self, 'proxy'):
            return
        ip_only = False
        # conservative IP detection
        try:
            if t:
                # try as IPv4/IPv6 or IP with port (strip port)
                candidate = t.split(':', 1)[0]
                ipaddress.ip_address(candidate)
                ip_only = True
        except Exception:
            ip_only = False

        self.proxy.setFilterText(t, ip_only=ip_only)

    def fetch_devices_df(self, use_cache=True):
        """Initiate fetching devices in a background worker thread"""
        # Don't start a new fetch if one is already in progress
        if self.is_fetching:
            logger.debug("Device fetch already in progress, skipping new request")
            return
        
        # Stop any existing worker thread
        if self.fetch_worker is not None and self.fetch_worker.isRunning():
            self.fetch_worker.quit()
            self.fetch_worker.wait()
        
        # Create and start the worker thread
        self.is_fetching = True
        self.fetch_worker = DeviceFetchWorker(use_cache=use_cache)
        
        # Share cache with worker
        self.fetch_worker.cached_df = self.cached_df
        self.fetch_worker.last_device_count = self.last_device_count
        
        # Connect signals
        self.fetch_worker.result.connect(self._on_fetch_complete)
        self.fetch_worker.error.connect(self._on_fetch_error)
        self.fetch_worker.finished.connect(self._on_fetch_finished)
        
        logger.debug("Starting background device fetch worker")
        self.fetch_worker.start()
    
    def _on_fetch_complete(self, df):
        """Handle successful device fetch from worker thread"""
        try:
            logger.debug("Received %d devices from worker thread", len(df))
            
            # Update cache from worker
            self.cached_df = df
            if self.fetch_worker:
                self.last_device_count = self.fetch_worker.last_device_count
            
            # Update UI with paginated model
            self.model.setDataFrame(df)
            try:
                self.table_view.resizeColumnsToContents()
                self.table_view.horizontalHeader().setStretchLastSection(True)
            except Exception:
                pass
            
            # Update pagination controls
            self._update_pagination_controls()
            
            self.update_chart(df)
            try:
                self.update_risk_level_counts()
            except Exception:
                logger.exception("Failed to update risk level counts")
            
            # Update filter panel with organizations and countries
            if self.advanced_filters:
                try:
                    # Check for both lowercase and capitalized column names
                    org_col = 'Org' if 'Org' in df.columns else 'org' if 'org' in df.columns else None
                    country_col = 'Country' if 'Country' in df.columns else 'country' if 'country' in df.columns else None
                    
                    orgs = df[org_col].dropna().unique().tolist() if org_col and org_col in df.columns else []
                    countries = df[country_col].dropna().unique().tolist() if country_col and country_col in df.columns else []
                    
                    if orgs:
                        self.advanced_filters.set_organizations(orgs)
                    if countries:
                        self.advanced_filters.set_countries(countries)
                    
                    logger.debug("Updated filters: %d orgs, %d countries", len(orgs), len(countries))
                except Exception as e:
                    logger.exception("Failed to update filter options: %s", e)
        except Exception as e:
            logger.exception("Error processing fetched devices: %s", e)
    
    def _on_fetch_error(self, error_msg):
        """Handle error from worker thread"""
        logger.error("Device fetch worker error: %s", error_msg)
        QMessageBox.warning(self, "Fetch Error", f"Failed to fetch devices: {error_msg}")
    
    def _on_fetch_finished(self):
        """Handle worker thread completion"""
        self.is_fetching = False
        logger.debug("Device fetch worker finished")

    def _update_pagination_controls(self):
        """Update pagination label and Load More button visibility/state"""
        try:
            displayed = self.model.get_displayed_rows()
            total = self.model.get_total_rows()
            self.pagination_label.setText(f"Showing {displayed} of {total} devices")
            
            # Show Load More button only if there are more rows to load
            has_more = displayed < total
            self.load_more_btn.setVisible(has_more)
            logger.debug("Pagination: %d/%d displayed, Load More visible=%s", displayed, total, has_more)
        except Exception as e:
            logger.exception("Failed to update pagination controls: %s", e)
    
    def _on_load_more_clicked(self):
        """Handle Load More button click"""
        try:
            has_more = self.model.load_more()
            self._update_pagination_controls()
            logger.info("Loaded more results, %d rows displayed", self.model.get_displayed_rows())
        except Exception as e:
            logger.exception("Failed to load more results: %s", e)
            QMessageBox.warning(self, "Load More Failed", f"Error loading more results: {str(e)}")

    def refresh(self):
        """Trigger a device data refresh using the background worker thread"""
        logger.debug("Refresh requested - starting background device fetch")
        self.fetch_devices_df(use_cache=False)  # Always fetch fresh on manual refresh
    
    def _run_training_with_message(self, message):
        """Helper to run training in background and show message on completion"""
        try:
            mod = importlib.import_module('model')
            if hasattr(mod, 'train_and_save_model'):
                mod.train_and_save_model()
                logger.info("Training completed successfully: %s", message)
                # Emit signal to main thread instead of direct QMessageBox
                self.training_completed.emit(message, True)
        except Exception as e:
            logger.exception("Training failed: %s", e)
            # Emit signal to main thread instead of direct QMessageBox
            self.training_completed.emit(f"Training failed: {str(e)}", False)

    def update_chart(self, df):
        # Draw a simple bar chart for risk distribution with counts and percentages (restored per user request)
        try:
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            # Dark theme colors for the chart
            self.figure.set_facecolor('#2d2d2d')
            ax.set_facecolor('#1e1e1e')
            ax.set_title('Device Risk Distribution', fontsize=14, weight='bold', pad=10, color='#e0e0e0')

            if df.empty:
                ax.text(0.5, 0.5, "No devices yet", ha='center', va='center', fontsize=12, color='#888')
                self.canvas.draw_idle()
                return

            risk_col = 'Risk' if 'Risk' in df.columns else 'risk'
            counts = df[risk_col].value_counts()
            order = ['High', 'Medium', 'Low']
            labels = [o for o in order]
            values = [int(counts.get(l, 0)) for l in labels]

            color_map = {'High': '#d9534f', 'Medium': '#f0ad4e', 'Low': '#5bc0de'}
            colors = [color_map.get(l, '#6c757d') for l in labels]
            bars = ax.bar(labels, values, color=colors, edgecolor='none', width=0.6)
            total = sum(values) if sum(values) > 0 else 1

            # Annotate bars with a single label: 'count (xx.x%)' centered above each bar.
            max_h = max(values) if values else 0
            for bar, val in zip(bars, values):
                h = bar.get_height()
                pct = (val / total) * 100 if total else 0
                label = f"{val} ({pct:.1f}%)"
                ax.annotate(label, xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 6), textcoords='offset points', ha='center', va='bottom', fontsize=11, weight='bold', color='#e0e0e0')

            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['left'].set_color('#444444')
            ax.spines['bottom'].set_color('#444444')
            ax.set_ylabel('Count', fontsize=11, color='#e0e0e0')
            ax.set_xlabel('Risk', fontsize=11, color='#e0e0e0')
            ax.yaxis.grid(True, linestyle='--', color='#444444', alpha=0.5)
            ax.set_axisbelow(True)
            ax.tick_params(axis='x', colors='#e0e0e0', labelsize=11)
            ax.tick_params(axis='y', colors='#e0e0e0', labelsize=10)
            # add headroom so annotations above bars aren't clipped
            ymin, ymax = ax.get_ylim()
            # Provide a uniform headroom so the 'count (pct%)' labels are not clipped.
            headroom = max(4, total * 0.25)
            ax.set_ylim(ymin, max(ymax, max_h + headroom))
            self.figure.tight_layout(pad=1.0)
            self.canvas.draw_idle()
            # Clean up matplotlib memory after rendering to prevent figure cache buildup
            plt.close(self.figure)
        except Exception:
            logger.exception("update_chart failed")

    def update_risk_level_counts(self):
        session = get_session()
        try:
            total_high = session.query(Device).filter(Device.risk_label == 2).count()
            unnotified_high = session.query(Device).filter(Device.risk_label == 2, Device.notified == False).count()

            total_medium = session.query(Device).filter(Device.risk_label == 1).count()
            unnotified_medium = session.query(Device).filter(Device.risk_label == 1, Device.notified == False).count()

            total_low = session.query(Device).filter(Device.risk_label == 0).count()
            unnotified_low = session.query(Device).filter(Device.risk_label == 0, Device.notified == False).count()

            total_all = session.query(Device).count()
            unnotified_all = session.query(Device).filter(Device.notified == False).count()

            self._alert_cat.clear()
            self._alert_cat.addItem(f"High: {total_high} ({unnotified_high} unnotified)")
            self._alert_cat.addItem(f"Medium: {total_medium} ({unnotified_medium} unnotified)")
            self._alert_cat.addItem(f"Low: {total_low} ({unnotified_low} unnotified)")
            self._alert_cat.addItem(f"All: {total_all} ({unnotified_all} unnotified)")
        finally:
            session.close()

    def scan_now(self):
        try:
            logger.info("Manual scan started.")
            q = None
            try:
                custom = self._shodan_query.text().strip()
                if custom:
                    q = custom
            except Exception:
                custom = None

            try:
                if q is None and hasattr(self, '_shodan_preset'):
                    idx = self._shodan_preset.currentIndex()
                    if idx > 0 and hasattr(self, '_shodan_preset_keys'):
                        key = self._shodan_preset_keys[idx - 1]
                        q = SHODAN_QUERIES.get(key)
            except Exception:
                pass

            used_default = False
            if not q:
                # Prefer an explicit SHODAN_QUERY (single global). If empty, use the
                # first preset value from SHODAN_QUERIES as the UI/default behavior.
                if SHODAN_QUERY and str(SHODAN_QUERY).strip():
                    q = SHODAN_QUERY
                else:
                    try:
                        q = next(iter(SHODAN_QUERIES.values()))
                    except Exception:
                        q = 'product:apache'
                used_default = True

            if used_default:
                QMessageBox.information(self, "Shodan Query", f"No query specified. Using default Shodan query: {q}")

            # Run scan in thread pool to avoid UI blocking
            logger.debug("Submitting scan to thread pool")
            future = _network_executor.submit(self._perform_scan, q)
            
            # Show progress message
            QMessageBox.information(self, "Scan", "Scan started in background. View will update when complete.")
            logger.info("Manual scan submitted to background thread.")
        except Exception as e:
            logger.exception("Manual scan failed: %s", e)
            QMessageBox.critical(self, "Scan error", str(e))
    
    def _perform_scan(self, query):
        """Execute Shodan and NVD scan in background thread"""
        scan_errors = []
        shodan_succeeded = False
        
        try:
            logger.info("Performing Shodan scan for query: %s", query)
            try:
                shodan_collector.scan_shodan(query=query)
                shodan_succeeded = True
            except Exception as shodan_error:
                logger.exception("Shodan scan failed: %s", shodan_error)
                scan_errors.append(f"Shodan scan failed: {str(shodan_error)}")
            
            # Only run NVD enrichment if Shodan succeeded
            if shodan_succeeded:
                logger.info("Performing NVD enrichment")
                try:
                    nvd_collector.enrich_devices_with_vulns()
                except Exception as nvd_error:
                    logger.exception("NVD enrichment failed: %s", nvd_error)
                    scan_errors.append(f"NVD enrichment failed: {str(nvd_error)}")
            else:
                logger.info("Skipping NVD enrichment due to Shodan scan failure")
            
            # Emit signal to main thread with error list
            logger.info("Manual scan finished, emitting completion signal")
            self.scan_completed.emit(scan_errors)
        except Exception as e:
            logger.exception("Scan execution failed: %s", e)
            # Emit signal with critical error
            self.scan_completed.emit([f"Scan failed with unexpected error: {str(e)}"])
    
    def _on_scan_completed(self, scan_errors):
        """Handle scan completion in main thread (slot called via signal)"""
        # Only refresh if scan partially or fully succeeded
        if not scan_errors:
            # All successful - refresh normally
            self.refresh()
            QMessageBox.information(self, "Scan Complete", 
                "Manual scan completed successfully. View is being refreshed.")
        else:
            # Scan had errors - still refresh but show what went wrong
            error_msg = "\n".join(scan_errors)
            self.refresh()
            # Show critical error if Shodan failed (since it's the primary data source)
            if "Shodan scan failed" in error_msg:
                QMessageBox.critical(self, "Scan Failed", 
                    f"Shodan scan failed and no new data was collected:\n\n{error_msg}")
            else:
                # NVD-only error (Shodan succeeded but enrichment had issues)
                QMessageBox.warning(self, "Scan Completed with Partial Errors", 
                    f"Scan had some issues during enrichment:\n\n{error_msg}\n\nDevices were updated but vulnerability data may be incomplete.")
    
    def _on_training_completed(self, message, is_success):
        """Handle training completion in main thread (slot called via signal)"""
        if is_success:
            QMessageBox.information(self, "Training", message)
        else:
            QMessageBox.critical(self, "Training Error", message)

    def upload_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to import", "", "Data files (*.csv *.json)")
        if not path:
            return
        try:
            if path.lower().endswith('.csv'):
                df = pd.read_csv(path)
            else:
                df = pd.read_json(path)
        except Exception as e:
            logger.exception("Failed to read uploaded file: %s", e)
            QMessageBox.critical(self, "Import error", f"Failed to read file: {e}")
            return
        # Flexible column lookup
        df_cols = {c.lower(): c for c in df.columns}

        def get_val(row, keys, default=None):
            for k in keys:
                if k in df_cols:
                    try:
                        v = row[df_cols[k]]
                    except Exception:
                        v = None
                    if pd.isna(v):
                        continue
                    return v
            return default

        # Identify IP column (common variants)
        ip_keys = ['ip', 'ip_address', 'ip address', 'address']
        ip_col_found = None
        for k in ip_keys:
            if k in df_cols:
                ip_col_found = df_cols[k]
                break

        if ip_col_found is None:
            QMessageBox.critical(self, "Import error", "No IP column found in uploaded file. Expected a column named 'ip' or similar.")
            return

        session = get_session()
        added = 0
        updated = 0
        skipped = 0
        total_rows = 0
        try:
            for _, row in df.iterrows():
                total_rows += 1
                try:
                    ip = str(row.get(ip_col_found) or '').strip()
                except Exception:
                    ip = ''
                if not ip:
                    skipped += 1
                    continue

                existing = session.query(Device).filter_by(ip=ip).one_or_none()

                def val_for(col, default=None):
                    v = get_val(row, [col])
                    return default if v is None else v

                if existing:
                    # Replace fields with new incoming values (if provided) — user requested replacement
                    existing.org = val_for('org', existing.org)
                    existing.country = val_for('country', existing.country)
                    try:
                        existing.num_open_ports = int(val_for('num_open_ports', existing.num_open_ports or 0))
                    except Exception:
                        existing.num_open_ports = existing.num_open_ports
                    try:
                        existing.cve_count = int(val_for('cve_count', existing.cve_count or 0))
                    except Exception:
                        existing.cve_count = existing.cve_count
                    try:
                        existing.max_cvss = float(val_for('max_cvss', existing.max_cvss or 0.0))
                    except Exception:
                        existing.max_cvss = existing.max_cvss
                    try:
                        existing.exposure_days = int(val_for('exposure_days', existing.exposure_days or 0))
                    except Exception:
                        existing.exposure_days = existing.exposure_days
                    lab = get_val(row, ['label', 'risk'], None)
                    if lab is not None and str(lab).strip() != '':
                        try:
                            existing.risk_label = int(lab)
                        except Exception:
                            pass
                    # --- Update advanced fields if provided ---
                    try:
                        existing.auth_failures_24h = int(val_for('auth_failures_24h', existing.auth_failures_24h or 0))
                    except Exception:
                        pass
                    try:
                        existing.traffic_anomaly_score = float(val_for('traffic_anomaly_score', existing.traffic_anomaly_score or 0.0))
                    except Exception:
                        pass
                    try:
                        existing.patch_lag_days = int(val_for('patch_lag_days', existing.patch_lag_days or 0))
                    except Exception:
                        pass
                    try:
                        existing.suspicious_activities_count = int(val_for('suspicious_activities_count', existing.suspicious_activities_count or 0))
                    except Exception:
                        pass
                    try:
                        existing.data_sensitivity_level = int(val_for('data_sensitivity_level', existing.data_sensitivity_level or 1))
                    except Exception:
                        pass
                    try:
                        existing.is_critical_service = bool(val_for('is_critical_service', existing.is_critical_service or False))
                    except Exception:
                        pass
                    existing.service_category = val_for('service_category', existing.service_category)
                    existing.infrastructure_type = val_for('infrastructure_type', existing.infrastructure_type)
                    existing.compliance_requirements = val_for('compliance_requirements', existing.compliance_requirements)
                    try:
                        existing.incident_history_count = int(val_for('incident_history_count', existing.incident_history_count or 0))
                    except Exception:
                        pass
                    existing.network_segment = val_for('network_segment', existing.network_segment)
                    try:
                        existing.firewall_rules_count = int(val_for('firewall_rules_count', existing.firewall_rules_count or 0))
                    except Exception:
                        pass
                    try:
                        existing.connected_critical_assets = int(val_for('connected_critical_assets', existing.connected_critical_assets or 0))
                    except Exception:
                        pass
                    updated += 1
                else:
                    try:
                        new_data = {
                            "ip": ip,
                            "org": val_for('org', ''),
                            "country": val_for('country', ''),
                            "num_open_ports": int(val_for('num_open_ports', 0) or 0),
                            "cve_count": int(val_for('cve_count', 0) or 0),
                            "max_cvss": float(val_for('max_cvss', 0.0) or 0.0),
                            "exposure_days": int(val_for('exposure_days', 0) or 0),
                            "risk_label": int(val_for('label', val_for('risk', 0) or 0)),
                            # advanced fields
                            "auth_failures_24h": int(val_for('auth_failures_24h', 0) or 0),
                            "traffic_anomaly_score": float(val_for('traffic_anomaly_score', 0.0) or 0.0),
                            "patch_lag_days": int(val_for('patch_lag_days', 0) or 0),
                            "suspicious_activities_count": int(val_for('suspicious_activities_count', 0) or 0),
                            "data_sensitivity_level": int(val_for('data_sensitivity_level', 1) or 1),
                            "is_critical_service": bool(val_for('is_critical_service', False)),
                            "service_category": val_for('service_category'),
                            "infrastructure_type": val_for('infrastructure_type'),
                            "compliance_requirements": val_for('compliance_requirements'),
                            "incident_history_count": int(val_for('incident_history_count', 0) or 0),
                            "network_segment": val_for('network_segment'),
                            "firewall_rules_count": int(val_for('firewall_rules_count', 0) or 0),
                            "connected_critical_assets": int(val_for('connected_critical_assets', 0) or 0),
                        }
                        new = Device(**{k: v for k, v in new_data.items() if v is not None})
                        session.add(new)
                        added += 1
                    except Exception:
                        logger.exception("Failed to add new device for IP %s", ip)
                        skipped += 1

            session.commit()
            QMessageBox.information(self, "Import", f"Processed {total_rows} rows. Added: {added}, Updated: {updated}, Skipped: {skipped}.")
            logger.info("Imported %d rows from %s -> added=%d updated=%d skipped=%d", total_rows, path, added, updated, skipped)
        except Exception as e:
            session.rollback()
            logger.exception("Import failed: %s", e)
            QMessageBox.critical(self, "Import error", str(e))
        finally:
            session.close()

        try:
            # Attempt to call training dynamically so upload doesn't fail when training module is absent
            try:
                mod = importlib.import_module('model')
                if hasattr(mod, 'train_and_save_model'):
                    # Run training in background thread to avoid UI freeze
                    training_thread = threading.Thread(
                        target=self._run_training_with_message,
                        args=("Model trained and stored from uploaded data.",),
                        daemon=True
                    )
                    training_thread.start()
                    logger.info("Post-upload training started in background thread")
                else:
                    logger.info("No train_and_save_model found in model package; skipping post-import training.")
            except Exception:
                logger.exception("Post-import training failed or training module missing; skipping.")
        except Exception:
            logger.exception("Training after import failed.")

        self.refresh()

    def manual_send_alerts(self):
        # Backward-compatible wrapper: call internal sender requiring explicit selection
        return self._manual_send_selected()

    def _manual_send_selected(self, category_text: str = None, mark_after: bool = None):
        """Send alerts for currently selected table rows.
        If category_text is provided, it will be included in the subject; if mark_after is provided,
        it will control whether devices are marked as notified after sending. Otherwise the UI state is used.
        """
        session = get_session()
        try:
            sel_model = self.table_view.selectionModel()
            if not sel_model or not sel_model.hasSelection():
                QMessageBox.information(self, "No selection", "Please select one or more rows in the table before using Send Selected.")
                return

            rows = sel_model.selectedRows()
            ips = []
            view_model = self.table_view.model()
            try:
                ip_col = list(self.model._df.columns).index('IP')
            except Exception:
                ip_col = 0
            # Log selected view indices for debugging
            try:
                sel_coords = [(i.row(), i.column()) for i in rows]
                logger.debug("Selected view indices: %s", sel_coords)
            except Exception:
                pass

            for idx in rows:
                try:
                    proxy_index = idx
                    # If the view model is a proxy, map the QModelIndex back to source
                    if isinstance(view_model, QSortFilterProxyModel):
                        src_index = view_model.mapToSource(proxy_index)
                        src_row = src_index.row()
                    else:
                        src_row = proxy_index.row()

                    # obtain IP from the source DataFrame
                    ip = None
                    try:
                        ip = self.model._df.iloc[src_row]['IP']
                    except Exception:
                        # fallback: read from view data cell
                        try:
                            data_idx = proxy_index.sibling(proxy_index.row(), ip_col)
                            ip = view_model.data(data_idx, Qt.DisplayRole)
                        except Exception:
                            ip = None

                    if not ip:
                        continue
                    ips.append(str(ip))
                except Exception:
                    logger.exception("Error mapping selected index to IP")
                    continue

            logger.debug("Selected IPs: %s", ips)

            if not ips:
                QMessageBox.information(self, "No devices", "Selected devices not found in DB.")
                return

            devices = session.query(Device).filter(Device.ip.in_(ips)).all()
            if not devices:
                QMessageBox.information(self, "No devices", "Selected devices not found in DB.")
                return

            subj_cat = category_text or (self._alert_cat.currentText() if hasattr(self, '_alert_cat') else '')
            subj_label = subj_cat.split(':', 1)[0] if subj_cat else 'Selected'

            ok = QMessageBox.question(self, "Confirm send", f"Send alerts for {len(devices)} selected device(s)?", QMessageBox.Yes | QMessageBox.No)
            if ok != QMessageBox.Yes:
                return

            html = build_device_summary(devices)
            subject = f"Manual alert - {subj_label} - {len(devices)} device(s)"
            send_email_alert(subject, html)

            mark_flag = (mark_after if mark_after is not None else (self._alert_mark.isChecked() if hasattr(self, '_alert_mark') else False))
            if mark_flag:
                for d in devices:
                    d.notified = True
                session.commit()

            QMessageBox.information(self, "Alerts sent", f"Sent alerts for {len(devices)} selected device(s).")
            logger.info("Selected manual alerts sent for %d devices", len(devices))
        except Exception as e:
            session.rollback()
            logger.exception("Failed to send manual alerts: %s", e)
            QMessageBox.critical(self, "Send failed", str(e))
        finally:
            session.close()

    def _show_send_selected_dialog(self):
        """Show a small dialog allowing the user to confirm and choose category/mark for sending selected devices."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Send Selected Devices")
        layout = QVBoxLayout()

        info = QLabel("Send alerts for currently selected devices. Choose a category label (optional) and whether to mark devices as notified.")
        info.setWordWrap(True)
        layout.addWidget(info)

        cat_combo = QComboBox()
        try:
            # copy current items
            for i in range(self._alert_cat.count()):
                cat_combo.addItem(self._alert_cat.itemText(i))
        except Exception:
            cat_combo.addItem('Selected')
        layout.addWidget(cat_combo)

        mark_chk = QCheckBox("Mark devices as notified after send")
        mark_chk.setChecked(self._alert_mark.isChecked() if hasattr(self, '_alert_mark') else False)
        layout.addWidget(mark_chk)

        btn_layout = QHBoxLayout()
        send_btn = QPushButton("Send")
        cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(send_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        dlg.setLayout(layout)

        def on_send():
            dlg.accept()

        def on_cancel():
            dlg.reject()

        send_btn.clicked.connect(on_send)
        cancel_btn.clicked.connect(on_cancel)

        dlg.resize(420, 180)
        if dlg.exec_() == QDialog.Accepted:
            sel_cat = cat_combo.currentText()
            sel_mark = mark_chk.isChecked()
            self._manual_send_selected(category_text=sel_cat, mark_after=sel_mark)

    def send_filtered_alerts(self):
        session = get_session()
        try:
            cat_text = self._alert_cat.currentText() if hasattr(self, '_alert_cat') else 'All'
            # Normalize category name (extract before ':' or '(' )
            cat = cat_text.split(':', 1)[0].split('(', 1)[0].strip() if cat_text else 'All'
            cat = cat.title()

            limit = int(self._alert_limit.value() if hasattr(self, '_alert_limit') else 50)
            mapping = {'High': 2, 'Medium': 1, 'Low': 0}

            q = session.query(Device).order_by(Device.id.asc())
            if cat and cat != 'All':
                target = mapping.get(cat, None)
                if target is None:
                    QMessageBox.information(self, "Invalid category", f"Unknown category selected: {cat}")
                    return
                q = q.filter(Device.risk_label == target)

            devices = q.limit(limit).all()
            if not devices:
                QMessageBox.information(self, "No devices", "No devices match the criteria.")
                return
            html = build_device_summary(devices)
            warning_subject = f"Manual alert - Filtered ({cat}) - {len(devices)} device(s) [duplicate alerts possible]"
            if not self._preview_and_confirm(subject=warning_subject, html=html):
                return
            send_email_alert(warning_subject, html)
            if hasattr(self, '_alert_mark') and self._alert_mark.isChecked():
                for d in devices:
                    d.notified = True
                session.commit()
            QMessageBox.information(self, "Alerts sent", f"Sent alerts for {len(devices)} device(s).")
            logger.info("Filtered alerts sent for %d devices (cat=%s)", len(devices), cat)
        except Exception as e:
            session.rollback()
            logger.exception("Failed to send filtered alerts: %s", e)
            QMessageBox.critical(self, "Send failed", str(e))
        finally:
            session.close()

    def send_all_alerts(self):
        session = get_session()
        try:
            ips = []
            try:
                ips = [str(x) for x in list(self.model._df['IP'])]
            except Exception:
                ips = []

            if ips:
                devices = session.query(Device).filter(Device.ip.in_(ips)).all()
            else:
                devices = session.query(Device).all()

            if not devices:
                QMessageBox.information(self, "No devices", "No devices available to send alerts for.")
                return

            html = build_device_summary(devices)
            subject = f"Manual alert - All devices ({len(devices)} total)"
            if not self._preview_and_confirm(subject=subject, html=html):
                return
            send_email_alert(subject, html)

            if hasattr(self, '_alert_mark') and self._alert_mark.isChecked():
                for d in devices:
                    d.notified = True
                session.commit()

            QMessageBox.information(self, "Alerts sent", f"Sent alerts for {len(devices)} device(s).")
            logger.info("Send-all alerts completed for %d devices", len(devices))
        except Exception as e:
            session.rollback()
            logger.exception("Failed to send all alerts: %s", e)
            QMessageBox.critical(self, "Send failed", str(e))
        finally:
            session.close()

    def train_model(self):
        # Check dataset has at least 2 classes before attempting training to avoid ValueError
        try:
            df = self.cached_df  # Use cached data directly (no fetch needed)
            if df is None or df.empty:
                QMessageBox.information(self, "Training", "No device data available to train on.")
                return
            # Look for risk labels (either numeric or textual)
            if 'risk' in df.columns and 'Risk' not in df.columns:
                labels = df['risk'].dropna().unique().tolist()
            elif 'Risk' in df.columns:
                labels = df['Risk'].dropna().unique().tolist()
            else:
                labels = []

            if len(labels) < 2:
                QMessageBox.warning(self, "Training", "Training requires at least two different risk classes (e.g. Low and High). Aborting training.")
                logger.info("Training aborted: insufficient class diversity (%d classes)", len(labels))
                return

            # Attempt to import training function dynamically so GUI works without the training script
            try:
                mod = importlib.import_module('model.training_orchestrator')
                if hasattr(mod, 'train_and_save_model'):
                    # Run training in background thread to avoid UI freeze
                    training_thread = threading.Thread(
                        target=self._run_training_with_message,
                        args=("Model trained and stored.",),
                        daemon=True
                    )
                    training_thread.start()
                    logger.info("Manual training started in background thread")
                else:
                    QMessageBox.information(self, "Training", "Training function not found in module.")
                    logger.info("Training function not found; skipping.")
            except Exception:
                logger.exception("Manual train failed due to missing training module or error.")
                QMessageBox.information(self, "Training", "Training module not available. Skipping.")
            self.refresh()
        except Exception as e:
            logger.exception("Manual train failed: %s", e)
            QMessageBox.critical(self, "Training error", str(e))

    def _preview_and_confirm(self, subject: str, html: str) -> bool:
        dlg = QDialog(self)
        dlg.setWindowTitle("Email Preview")
        dlg_layout = QVBoxLayout()
        subj_label = QLabel(f"<b>Subject:</b> {subject}")
        dlg_layout.addWidget(subj_label)
        browser = QTextBrowser()
        browser.setHtml(html)
        dlg_layout.addWidget(browser)
        btn_layout = QHBoxLayout()
        send_btn = QPushButton("Send")
        cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(send_btn)
        btn_layout.addWidget(cancel_btn)
        dlg_layout.addLayout(btn_layout)
        dlg.setLayout(dlg_layout)

        confirmed = {'val': False}

        def on_send():
            confirmed['val'] = True
            dlg.accept()

        def on_cancel():
            dlg.reject()

        send_btn.clicked.connect(on_send)
        cancel_btn.clicked.connect(on_cancel)

        dlg.resize(800, 600)
        res = dlg.exec_()
        return confirmed['val']


def start_gui(dark_theme=False):
    try:
        # Check if QApplication already exists
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        # Apply theme
        if THEME_MANAGER_AVAILABLE:
            if dark_theme:
                ThemeManager.apply_dark_theme(app)
            else:
                ThemeManager.apply_light_theme(app)
        
        try:
            logger.info("Initializing database for GUI...")
            init_db()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize database: %s", str(e))
            # Continue anyway - GUI can work with degraded functionality
        
        win = DashboardWindow()
        
        # Set window size to 25% wider than default for better visibility
        # Default width is typically 1200, make it 1500 (1200 * 1.25)
        default_width = 1200
        default_height = 700
        width = int(default_width * 1.25)  # 25% wider
        height = default_height
        win.resize(width, height)
        
        win.show()
        sys.exit(app.exec_())
    except Exception as e:
        logger.error("Failed to start GUI: %s", str(e))
        raise


if __name__ == "__main__":
    start_gui()

