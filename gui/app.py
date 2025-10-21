# Clean gui.app
import sys
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableView, QMessageBox, QHeaderView, QFileDialog, QComboBox, QSpinBox,
    QCheckBox, QTextBrowser, QDialog, QLineEdit, QSizePolicy
)
from PyQt5.QtCore import QTimer, Qt, QAbstractTableModel, QSortFilterProxyModel
from PyQt5.QtGui import QColor, QFont
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from db import get_session, Device, init_db
from email_alerts import send_email_alert, build_device_summary
from collectors import shodan_collector, nvd_collector
from config import SHODAN_QUERIES, DEFAULT_SHODAN_QUERY_KEY, SHODAN_QUERY
from logger import get_logger
import importlib
import ipaddress

logger = get_logger("gui")


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
        if role == Qt.TextAlignmentRole:
            col_name = self._df.columns[index.column()]
            if col_name in ('S.No', 'Open Ports', 'CVE Count', 'Max CVSS'):
                return Qt.AlignCenter
            if col_name == 'IP':
                return Qt.AlignLeft | Qt.AlignVCenter
            return Qt.AlignCenter
        if role == Qt.BackgroundRole:
            try:
                if 'Risk' in self._df.columns:
                    # Use label-based access to avoid pandas FutureWarning about integer keys
                    row_idx = self._df.index[index.row()]
                    risk = str(self._df.at[row_idx, 'Risk']).lower()
                    if 'high' in risk:
                        return QColor('#ffd6d6')
                    if 'medium' in risk:
                        return QColor('#fff4d6')
                    if 'low' in risk:
                        return QColor('#e6f7ff')
            except Exception:
                return None
        return None


class DashboardWindow(QWidget):
    def __init__(self, refresh_interval_ms=60000):
        super().__init__()
        self.setWindowTitle('Threat Sentric AI - Dashboard')
        self.layout = QVBoxLayout(self)

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
        self.model = PandasModel(pd.DataFrame())
        # Use a proxy model so we can filter across multiple columns
        class MultiColumnFilterProxy(QSortFilterProxyModel):
            """Fast multi-column filter that precomputes a boolean mask using
            vectorized pandas operations whenever the filter text changes.

            This avoids expensive per-keystroke Python loops for large DataFrames.
            """
            def __init__(self, parent=None):
                super().__init__(parent)
                self._filter_text = ''
                self._ip_only = False
                self._cols = []
                self._col_indices = []
                self._mask = None

            def setSourceModel(self, model):
                super().setSourceModel(model)
                try:
                    self._cols = list(model._df.columns)
                except Exception:
                    self._cols = []

            def setFilterText(self, text: str, ip_only: bool = False):
                t = (text or '').strip()
                self._filter_text = t.lower()
                self._ip_only = bool(ip_only)

                # Refresh column list from the current source model in case the model's
                # DataFrame was replaced (e.g., after refresh). This prevents stale
                # column metadata from causing the mask to be built against wrong cols.
                try:
                    src = self.sourceModel()
                    self._cols = list(src._df.columns) if hasattr(src, '_df') else []
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

                # build a boolean mask quickly using pandas vectorized string contains
                try:
                    df = self.sourceModel()._df
                    if not self._filter_text:
                        self._mask = None
                    else:
                        ft = self._filter_text
                        masks = None
                        for ci in self._col_indices:
                            col = df.iloc[:, ci].astype(str).fillna('').str.lower()
                            m = col.str.contains(ft, regex=False)
                            masks = m if masks is None else (masks | m)
                        self._mask = masks if masks is not None else pd.Series([False] * len(df))
                except Exception:
                    self._mask = None

                self.invalidateFilter()

            def filterAcceptsRow(self, source_row: int, source_parent) -> bool:
                if self._mask is None:
                    return True
                try:
                    return bool(self._mask.iat[source_row])
                except Exception:
                    return True

        self.proxy = MultiColumnFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table_view.setModel(self.proxy)
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
        self.layout.addWidget(self.table_view, 3)

        self.figure = Figure(figsize=(8, 3))
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas, 2)

        self.status_label = QLabel("")
        self.layout.addWidget(self.status_label)

        self.timer = QTimer()
        self.timer.setInterval(refresh_interval_ms)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

        self.refresh()

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

    def fetch_devices_df(self):
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
        return pd.DataFrame(rows)

    def refresh(self):
        try:
            df = self.fetch_devices_df()
            self.model.setDataFrame(df)
            try:
                self.table_view.resizeColumnsToContents()
                self.table_view.horizontalHeader().setStretchLastSection(True)
            except Exception:
                pass
            self.update_chart(df)
            try:
                self.update_risk_level_counts()
            except Exception:
                logger.exception("Failed to update risk level counts")
            logger.info("GUI refreshed.")
            count = len(df.index)
            from datetime import datetime
            self.status_label.setText(f"Devices: {count}  |  Refreshed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except Exception as e:
            logger.exception("GUI refresh failed: %s", e)

    def update_chart(self, df):
        # Draw a simple bar chart for risk distribution with counts and percentages (restored per user request)
        try:
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            self.figure.set_facecolor('#f7f9fb')
            ax.set_facecolor('#ffffff')
            ax.set_title('Device Risk Distribution', fontsize=14, weight='bold', pad=10)

            if df.empty:
                ax.text(0.5, 0.5, "No devices yet", ha='center', va='center', fontsize=12, color='#666')
                self.canvas.draw()
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
                ax.annotate(label, xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 6), textcoords='offset points', ha='center', va='bottom', fontsize=11, weight='bold', color='#222')

            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['left'].set_visible(False)
            ax.spines['bottom'].set_color('#e6e9ef')
            ax.set_ylabel('Count', fontsize=11)
            ax.set_xlabel('Risk', fontsize=11)
            ax.yaxis.grid(True, linestyle='--', color='#e9edf2')
            ax.set_axisbelow(True)
            ax.tick_params(axis='x', colors='#333', labelsize=11)
            ax.tick_params(axis='y', colors='#333', labelsize=10)
            # add headroom so annotations above bars aren't clipped
            ymin, ymax = ax.get_ylim()
            # Provide a uniform headroom so the 'count (pct%)' labels are not clipped.
            headroom = max(4, total * 0.25)
            ax.set_ylim(ymin, max(ymax, max_h + headroom))
            self.figure.tight_layout(pad=1.0)
            self.canvas.draw()
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
                q = SHODAN_QUERY or SHODAN_QUERIES.get(DEFAULT_SHODAN_QUERY_KEY, 'product:apache')
                used_default = True

            if used_default:
                QMessageBox.information(self, "Shodan Query", f"No query specified. Using default Shodan query: {q}")

            shodan_collector.scan_shodan(query=q)
            try:
                nvd_collector.enrich_devices_with_vulns()
            except Exception:
                logger.exception("NVD enrichment (manual) failed.")
            self.refresh()
            logger.info("Manual scan finished.")
            QMessageBox.information(self, "Scan", "Manual scan complete. Refreshing view.")
        except Exception as e:
            logger.exception("Manual scan failed: %s", e)
            QMessageBox.critical(self, "Scan error", str(e))

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
                    mod.train_and_save_model()
                    QMessageBox.information(self, "Training", "Model trained and stored from uploaded data.")
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
            df = self.fetch_devices_df()
            if df.empty:
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
                    mod.train_and_save_model()
                    QMessageBox.information(self, "Training", "Model trained and stored.")
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


def start_gui():
    app = QApplication(sys.argv)
    init_db()
    win = DashboardWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    start_gui()

