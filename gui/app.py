# gui/app.py
import sys
import pandas as pd
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableView, QMessageBox, QHeaderView, QFileDialog, QComboBox, QSpinBox, QCheckBox, QTextBrowser, QDialog
from PyQt5.QtCore import QTimer, Qt, QAbstractTableModel
from PyQt5.QtGui import QColor, QFont
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from db import get_session, Device, init_db
from email_alerts import send_email_alert, build_device_summary
from collectors import shodan_collector, nvd_collector
from config import MAX_SHODAN_RESULTS
from logger import get_logger
from model.trainer import train_and_save_model
from email_alerts import notify_new_high_risk_devices

logger = get_logger("gui")

class PandasModel(QAbstractTableModel):
    def __init__(self, df=pd.DataFrame()):
        super().__init__()
        self._df = df

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
        # Align numbers center/right, text left
        if role == Qt.DisplayRole:
            return str(value)
        if role == Qt.TextAlignmentRole:
            # center numeric columns
            col_name = self._df.columns[index.column()]
            if col_name in ('S.No', 'Open Ports', 'CVE Count', 'Max CVSS'):
                return Qt.AlignCenter
            if col_name == 'IP':
                return Qt.AlignLeft | Qt.AlignVCenter
            return Qt.AlignCenter
        if role == Qt.BackgroundRole:
            # color rows by Risk (High/Medium/Low)
            try:
                if 'Risk' in self._df.columns:
                    risk = str(self._df.iloc[index.row()]['Risk'])
                else:
                    risk = str(self._df.iloc[index.row()].get('risk', ''))
                if risk == 'High':
                    return QColor('#fff1f0')
                if risk == 'Medium':
                    return QColor('#fffaf0')
                if risk == 'Low':
                    return QColor('#f0fbff')
            except Exception:
                return None
        return None

    def setDataFrame(self, df):
        self.beginResetModel()
        # create a copy and map internal column names to user-friendly headers
        df2 = df.copy()
        rename_map = {
            'ip': 'IP',
            'org': 'Org',
            'country': 'Country',
            'open_ports': 'Open Ports',
            'cve_count': 'CVE Count',
            'max_cvss': 'Max CVSS',
            'risk': 'Risk',
            'last_seen': 'Last Seen'
        }
        new_cols = []
        for c in df2.columns:
            new_cols.append(rename_map.get(c, c.replace('_', ' ').title()))
        df2.columns = new_cols
        # reset index to ensure row order is stable and insert explicit serial number
        df2 = df2.reset_index(drop=True)
        if len(df2) > 0:
            df2.insert(0, 'S.No', list(range(1, len(df2) + 1)))
        else:
            # create an empty S.No column so header exists
            df2.insert(0, 'S.No', pd.Series(dtype='int'))
        self._df = df2
        self.endResetModel()

class DashboardWindow(QWidget):
    def __init__(self, refresh_interval_ms=30000):
        super().__init__()
        self.setWindowTitle("Threat Hunting Dashboard")
        self.resize(1000, 700)
        # improved styling: darker chrome, clear white table with styled headers
        self.setStyleSheet("""
            QWidget { background: #1b1b1b; color: #e6e6e6; font-family: Arial, Helvetica, sans-serif; }
            QPushButton { background: #2b7a78; color: #fff; border-radius:4px; padding:6px 10px; margin:2px; }
            QPushButton:hover { background: #3aa99f; }
            QTableView { background: #ffffff; color: #111111; gridline-color: #e0e0e0; }
            QHeaderView::section { background-color: #2f3640; color: #ffffff; padding:6px; border: 1px solid #444; font-weight:600; }
            QTableView::item { padding:6px; }
            QTableView::item:selected { background-color: #cfeefd; color: #000; }
        """)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        header = QHBoxLayout()
        # left-side controls
        scan_btn = QPushButton("Scan Now")
        scan_btn.clicked.connect(self.scan_now)
        header.addWidget(scan_btn)
        upload_btn = QPushButton("Upload CSV/JSON")
        upload_btn.clicked.connect(self.upload_file)
        header.addWidget(upload_btn)

        # title in the center
        header.addWidget(QLabel("<h2>Threat Hunting Dashboard</h2>"))
        header.addStretch()

        # right-side quick actions
        refresh_btn = QPushButton("Refresh Now")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        train_btn = QPushButton("Train Model (Manual)")
        train_btn.clicked.connect(self.train_model)
        header.addWidget(train_btn)

        filtered_btn = QPushButton("Send Filtered Alerts")
        filtered_btn.setToolTip("Send alerts for devices matching selected Category and Limit.")
        filtered_btn.clicked.connect(lambda: self.send_filtered_alerts())
        header.addWidget(filtered_btn)

        notify_btn = QPushButton("Send Alerts (All)")
        notify_btn.setToolTip("Send alerts for all devices currently in the dashboard (ignores category/limit).")
        notify_btn.clicked.connect(lambda: self.send_all_alerts())
        header.addWidget(notify_btn)

        # Manual alert controls (category, limit, mark-as-notified, send)
        header.addWidget(QLabel("Category:"))
        self._alert_cat = QComboBox()
        self._alert_cat.setToolTip("Select category to include in manual alerts")
        header.addWidget(self._alert_cat)
        
        # Initialize the combo box with placeholders until we get the counts
        self._alert_cat.addItems(["High: loading", "Medium: loading", "Low: loading", "All: loading"])
        
        header.addWidget(QLabel("Limit:"))
        self._alert_limit = QSpinBox()
        self._alert_limit.setRange(1, 1000)
        self._alert_limit.setValue(50)
        self._alert_limit.setToolTip("Maximum number of devices to include in the alert")
        header.addWidget(self._alert_limit)

        # Add mark-as-notified checkbox
        self._alert_mark = QCheckBox("Mark as notified")
        self._alert_mark.setToolTip("Mark devices as notified after sending (prevents duplicate alerts)")
        header.addWidget(self._alert_mark)

        # Add send alerts button
        send_alerts_btn = QPushButton("Send Selected Alerts")
        header.addWidget(send_alerts_btn)
        send_alerts_btn.clicked.connect(self.manual_send_alerts)

        self.layout.addLayout(header)

        # Status / info label
        self.status_label = QLabel("")
        self.layout.addWidget(self.status_label)

        self.table_view = QTableView()
        self.model = PandasModel(pd.DataFrame())
        self.table_view.setModel(self.model)
        # Visual improvements
        self.table_view.setAlternatingRowColors(True)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # hide row numbers and make headers visually distinct
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.horizontalHeader().setStyleSheet("QHeaderView::section { background-color: #2f3640; color: #ffffff; padding:8px; }")
        # header appearance
        header_font = QFont('Arial', 10, QFont.Bold)
        self.table_view.horizontalHeader().setFont(header_font)
        self.table_view.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.table_view.horizontalHeader().setFixedHeight(36)
        # enable sorting
        self.table_view.setSortingEnabled(True)
        # allow resizing last section
        self.table_view.horizontalHeader().setStretchLastSection(True)
        # slightly larger rows for readability
        self.table_view.verticalHeader().setDefaultSectionSize(28)
        self.layout.addWidget(self.table_view, 2)

        self.figure = Figure(figsize=(5,3))
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas, 1)

        self.timer = QTimer()
        self.timer.setInterval(refresh_interval_ms)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

        self.refresh()

    def fetch_devices_df(self):
        session = get_session()
        devices = session.query(Device).all()
        rows = []
        for d in devices:
            risk_text = {0:"Low",1:"Medium",2:"High"}.get(d.risk_label, "Unknown")
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
        df = pd.DataFrame(rows)
        return df

    def refresh(self):
        try:
            df = self.fetch_devices_df()
            self.model.setDataFrame(df)
            # resize columns to contents for readability, keep last column stretched
            try:
                self.table_view.resizeColumnsToContents()
                self.table_view.horizontalHeader().setStretchLastSection(True)
            except Exception:
                pass
            self.update_chart(df)
            # Update the risk level counts in the dropdown
            try:
                self.update_risk_level_counts()
            except Exception:
                logger.exception("Failed to update risk level counts")
            logger.info("GUI refreshed.")
            # update status
            count = len(df.index)
            from datetime import datetime
            self.status_label.setText(f"Devices: {count}  |  Refreshed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except Exception as e:
            logger.exception("GUI refresh failed: %s", e)

    def update_risk_level_counts(self):
        """Update the risk level dropdown with current device counts."""
        session = get_session()
        try:
            # Get counts for each risk level (total and unnotified)
            total_high = session.query(Device).filter(Device.risk_label == 2).count()
            unnotified_high = session.query(Device).filter(Device.risk_label == 2, Device.notified == False).count()

            total_medium = session.query(Device).filter(Device.risk_label == 1).count()
            unnotified_medium = session.query(Device).filter(Device.risk_label == 1, Device.notified == False).count()

            total_low = session.query(Device).filter(Device.risk_label == 0).count()
            unnotified_low = session.query(Device).filter(Device.risk_label == 0, Device.notified == False).count()

            total_all = session.query(Device).count()
            unnotified_all = session.query(Device).filter(Device.notified == False).count()

            # Update dropdown items showing both total and unnotified counts
            self._alert_cat.clear()
            self._alert_cat.addItem(f"High: {total_high} ({unnotified_high} unnotified)")
            self._alert_cat.addItem(f"Medium: {total_medium} ({unnotified_medium} unnotified)")
            self._alert_cat.addItem(f"Low: {total_low} ({unnotified_low} unnotified)")
            self._alert_cat.addItem(f"All: {total_all} ({unnotified_all} unnotified)")
        finally:
            session.close()

    def scan_now(self):
        """Manually trigger a Shodan scan and NVD enrichment, then refresh GUI."""
        try:
            logger.info("Manual scan started.")
            # perform scan (collector handles API key checks)
            shodan_collector.scan_shodan()
            # enrich with NVD data if available
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
        """Upload CSV or JSON and upsert into devices table, then optionally train."""
        path, _ = QFileDialog.getOpenFileName(self, "Select file to import", "", "Data files (*.csv *.json)")
        if not path:
            return
        try:
            if path.lower().endswith('.csv'):
                df = pd.read_csv(path)
            else:
                # assume JSON array or object
                df = pd.read_json(path)
        except Exception as e:
            logger.exception("Failed to read uploaded file: %s", e)
            QMessageBox.critical(self, "Import error", f"Failed to read file: {e}")
            return

        # Required column: ip. Optional: org, country, num_open_ports, cve_count, max_cvss, exposure_days, label/risk
        session = get_session()
        imported = 0
        try:
            for _, row in df.iterrows():
                ip = str(row.get('ip') or row.get('ip_address') or '').strip()
                if not ip:
                    continue
                existing = session.query(Device).filter_by(ip=ip).one_or_none()
                def val(col, default=None):
                    v = row.get(col)
                    return default if v is None else v

                if existing:
                    existing.org = val('org', existing.org)
                    existing.country = val('country', existing.country)
                    existing.num_open_ports = int(val('num_open_ports', existing.num_open_ports or 0))
                    existing.cve_count = int(val('cve_count', existing.cve_count or 0))
                    existing.max_cvss = float(val('max_cvss', existing.max_cvss or 0.0))
                    existing.exposure_days = int(val('exposure_days', existing.exposure_days or 0))
                    # allow label column names
                    lab = row.get('label') if 'label' in row else row.get('risk')
                    if lab is not None:
                        existing.risk_label = int(lab)
                else:
                    d = Device(
                        ip=ip,
                        org=val('org', ''),
                        country=val('country', ''),
                        num_open_ports=int(val('num_open_ports', 0)),
                        cve_count=int(val('cve_count', 0)),
                        max_cvss=float(val('max_cvss', 0.0)),
                        exposure_days=int(val('exposure_days', 0)),
                        risk_label=int(val('label', val('risk', 0)))
                    )
                    session.add(d)
                imported += 1
            session.commit()
            QMessageBox.information(self, "Import", f"Imported/updated {imported} rows.")
            logger.info("Imported %d rows from %s", imported, path)
        except Exception as e:
            session.rollback()
            logger.exception("Import failed: %s", e)
            QMessageBox.critical(self, "Import error", str(e))
        finally:
            session.close()

        # After import, train model automatically if there is data
        try:
            train_and_save_model()
            QMessageBox.information(self, "Training", "Model trained and stored from uploaded data.")
        except Exception:
            logger.exception("Training after import failed.")

        self.refresh()

    def update_chart(self, df):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        # polished chart look
        self.figure.set_facecolor('#f0f2f5')
        ax.set_facecolor('#ffffff')
        if df.empty:
            ax.text(0.5, 0.5, "No devices yet", ha='center', va='center', fontsize=12, color='#444')
        else:
            # prefer 'Risk' (capitalized) since DataFrame columns are prettified by setDataFrame
            risk_col = 'Risk' if 'Risk' in df.columns else 'risk'
            counts = df[risk_col].value_counts()
            # ensure consistent ordering
            order = ['High', 'Medium', 'Low']
            labels = [o for o in order]
            values = [int(counts.get(l, 0)) for l in labels]
            color_map = {'High': '#d9534f', 'Medium': '#f0ad4e', 'Low': '#5bc0de'}
            colors = [color_map.get(l, '#6c757d') for l in labels]
            bars = ax.bar(labels, values, color=colors, edgecolor='none')
            # remove spines and tidy axes
            for sp in ('top', 'right'):
                ax.spines[sp].set_visible(False)
            ax.spines['left'].set_visible(False)
            ax.spines['bottom'].set_color('#cccccc')
            ax.tick_params(axis='x', colors='#333', labelsize=11)
            ax.tick_params(axis='y', colors='#333')
            ax.set_xlabel('Risk', fontsize=12)
            ax.set_ylabel('Count', fontsize=12)
            ax.set_title('Device Risk Distribution', fontsize=14, pad=12)
            ax.grid(axis='y', linestyle='--', alpha=0.25)
            # annotate bar values
            for bar in bars:
                h = bar.get_height()
                if h > 0:
                    ax.annotate(f'{h}', xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 6), textcoords='offset points', ha='center', va='bottom', fontsize=10, color='#111')
            self.figure.tight_layout(pad=1.0)
        self.canvas.draw()

    def manual_send_alerts(self):
        """Send alerts for selected rows only. If none selected, ask user to use filters or send all."""
        session = get_session()
        try:
            sel_model = self.table_view.selectionModel()
            if not sel_model or not sel_model.hasSelection():
                # Ask user whether to route to filtered send, send all, or cancel
                resp = QMessageBox.question(self, "No selection", "No rows selected.\nYes = Use Category+Limit filters\nNo = Send all visible devices\nCancel = Do nothing", QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
                if resp == QMessageBox.Cancel:
                    return
                if resp == QMessageBox.Yes:
                    self.send_filtered_alerts()
                    return
                # No -> send all visible
                self.send_all_alerts()
                return

            rows = sel_model.selectedRows()
            ips = []
            for r in rows:
                try:
                    ip = self.model._df.iloc[r.row()]['IP']
                    ips.append(str(ip))
                except Exception:
                    continue

            if not ips:
                QMessageBox.information(self, "No devices", "Selected devices not found in DB.")
                return

            devices = session.query(Device).filter(Device.ip.in_(ips)).all()
            if not devices:
                QMessageBox.information(self, "No devices", "Selected devices not found in DB.")
                return

            ok = QMessageBox.question(self, "Confirm send", f"Send alerts for {len(devices)} selected device(s)?", QMessageBox.Yes | QMessageBox.No)
            if ok != QMessageBox.Yes:
                return

            html = build_device_summary(devices)
            subject = f"Manual alert - Selected - {len(devices)} device(s)"
            send_email_alert(subject, html)

            if hasattr(self, '_alert_mark') and self._alert_mark.isChecked():
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

    def send_filtered_alerts(self):
        """Send alerts for devices matching the Category + Limit controls after confirmation."""
        session = get_session()
        try:
            cat_text = self._alert_cat.currentText() if hasattr(self, '_alert_cat') else 'All'
            # Support multiple dropdown formats:
            #  - 'High: 132 (20 unnotified)'
            #  - 'High (20 devices)'
            #  - 'High'
            cat = cat_text
            if ':' in cat_text:
                # 'High: 132 (20 unnotified)' -> 'High'
                cat = cat_text.split(':', 1)[0].strip()
            elif '(' in cat_text:
                # 'High (20 devices)' -> 'High'
                cat = cat_text.split(' (', 1)[0].strip()
            
            limit = self._alert_limit.value() if hasattr(self, '_alert_limit') else 50
            mapping = {'High': 2, 'Medium': 1, 'Low': 0}
            
            # NOTE: user requested sending to all devices regardless of notified status
            # so do not filter by Device.notified here (this may send duplicate alerts).
            q = session.query(Device)
            if cat != 'All':
                q = q.filter(Device.risk_label == mapping.get(cat, -1))
            else:
                # When "All" is selected, sort by risk_label in descending order (High to Low)
                q = q.order_by(Device.risk_label.desc())
            
            devices = q.limit(limit).all()
            if not devices:
                QMessageBox.information(self, "No devices", "No devices match the criteria.")
                return
            html = build_device_summary(devices)
            # preview & confirm - include a short warning in the subject/body to note duplicates may occur
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
        """Send alerts for all devices currently shown in the dashboard table (ignores category/limit).

        This queries the model's DataFrame and maps IPs back to Device objects to ensure build_device_summary
        receives full SQLAlchemy Device objects (with vulnerabilities when present).
        """
        session = get_session()
        try:
            # Build list of IPs from the current model DataFrame
            ips = []
            try:
                ips = [str(x) for x in list(self.model._df['IP'])]
            except Exception:
                # fallback: fetch all DB devices
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

            # Do not auto-mark notified here unless user explicitly requested via checkbox
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
        try:
            train_and_save_model()
            QMessageBox.information(self, "Training", "Model trained and stored.")
            self.refresh()
        except Exception as e:
            logger.exception("Manual train failed: %s", e)
            QMessageBox.critical(self, "Training error", str(e))

    def _preview_and_confirm(self, subject: str, html: str) -> bool:
        """Show an HTML preview dialog (QDialog with QTextBrowser) and return True if user confirms sending."""
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
