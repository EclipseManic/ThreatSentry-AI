"""
Enhanced Dashboard Module - Advanced Analytics and Visualization

Provides extended features for the threat hunting dashboard:
- Advanced analytics (top vulnerable organizations, risk trends, CVE distribution)
- Geographic risk mapping
- Enhanced filtering (CVSS range, organization, country)
- Dark theme option
- Export functionality (PDF/CSV)
- Model training status
- Remediation suggestions
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
import json
import io

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, 
    QPushButton, QSpinBox, QComboBox, QCheckBox, QFileDialog,
    QMessageBox, QSlider, QGridLayout, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtPrintSupport import QPrinter, QPdfWriter
from PyQt5.QtCore import QIODevice

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

from data import get_session, Device
from core import get_logger

logger = get_logger("enhanced_dashboard")


class AnalyticsEngine:
    """Generate advanced analytics from device data"""
    
    def __init__(self, session=None):
        self.session = session or get_session()
    
    def get_top_vulnerable_organizations(self, limit=10) -> List[Dict]:
        """Get organizations with highest risk devices"""
        try:
            devices = self.session.query(Device).all()
            if not devices:
                return []
            
            org_risks = {}
            org_counts = {}
            
            for device in devices:
                org = device.org or "Unknown"
                risk_value = self._risk_to_numeric(device.risk_label)
                
                org_risks[org] = org_risks.get(org, 0) + risk_value
                org_counts[org] = org_counts.get(org, 0) + 1
            
            # Calculate average risk per organization
            org_avg_risk = {
                org: org_risks[org] / org_counts[org]
                for org in org_risks
            }
            
            sorted_orgs = sorted(org_avg_risk.items(), key=lambda x: x[1], reverse=True)
            return [
                {"org": org, "avg_risk": risk, "device_count": org_counts[org]}
                for org, risk in sorted_orgs[:limit]
            ]
        except Exception as e:
            logger.error("Failed to get top vulnerable organizations: %s", e)
            return []
    
    def get_risk_trends(self, days=30) -> Dict:
        """Get risk trends over time"""
        try:
            devices = self.session.query(Device).all()
            if not devices:
                return {}
            
            trends = {}
            today = datetime.now().date()
            
            for i in range(days):
                date = today - timedelta(days=i)
                date_str = date.isoformat()
                trends[date_str] = {"high": 0, "medium": 0, "low": 0}
            
            # Simulate trends (in production, would use actual historical data)
            for device in devices:
                if hasattr(device, 'last_analysis_date') and device.last_analysis_date:
                    date_str = device.last_analysis_date.date().isoformat()
                    if date_str in trends:
                        risk = str(device.risk_label).lower()
                        if "2" in str(device.risk_label):
                            trends[date_str]["high"] += 1
                        elif "1" in str(device.risk_label):
                            trends[date_str]["medium"] += 1
                        else:
                            trends[date_str]["low"] += 1
            
            return dict(sorted(trends.items()))
        except Exception as e:
            logger.error("Failed to get risk trends: %s", e)
            return {}
    
    def get_cve_severity_distribution(self) -> Dict[str, int]:
        """Get CVE severity distribution"""
        try:
            devices = self.session.query(Device).all()
            if not devices:
                return {}
            
            distribution = {
                "Critical (9.0-10.0)": 0,
                "High (7.0-8.9)": 0,
                "Medium (4.0-6.9)": 0,
                "Low (0.1-3.9)": 0,
                "None (0.0)": 0
            }
            
            for device in devices:
                if device.max_cvss is None or device.max_cvss == 0:
                    distribution["None (0.0)"] += 1
                elif device.max_cvss >= 9.0:
                    distribution["Critical (9.0-10.0)"] += 1
                elif device.max_cvss >= 7.0:
                    distribution["High (7.0-8.9)"] += 1
                elif device.max_cvss >= 4.0:
                    distribution["Medium (4.0-6.9)"] += 1
                else:
                    distribution["Low (0.1-3.9)"] += 1
            
            return distribution
        except Exception as e:
            logger.error("Failed to get CVE severity distribution: %s", e)
            return {}
    
    def get_geographic_risk_distribution(self) -> Dict[str, Dict]:
        """Get risk distribution by country"""
        try:
            devices = self.session.query(Device).all()
            if not devices:
                return {}
            
            geographic = {}
            
            for device in devices:
                country = device.country or "Unknown"
                if country not in geographic:
                    geographic[country] = {"high": 0, "medium": 0, "low": 0, "total": 0}
                
                risk = str(device.risk_label).lower()
                if "2" in str(device.risk_label):
                    geographic[country]["high"] += 1
                elif "1" in str(device.risk_label):
                    geographic[country]["medium"] += 1
                else:
                    geographic[country]["low"] += 1
                geographic[country]["total"] += 1
            
            return dict(sorted(geographic.items(), key=lambda x: x[1]["total"], reverse=True))
        except Exception as e:
            logger.error("Failed to get geographic risk distribution: %s", e)
            return {}
    
    @staticmethod
    def _risk_to_numeric(risk_label) -> float:
        """Convert risk label to numeric value"""
        if risk_label is None:
            return 0
        risk_str = str(risk_label).lower()
        if "2" in str(risk_label) or "high" in risk_str:
            return 2.0
        elif "1" in str(risk_label) or "medium" in risk_str:
            return 1.0
        else:
            return 0.0


class AdvancedFilterPanel(QWidget):
    """Advanced filtering widget"""
    
    filters_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QHBoxLayout(self)
        
        # CVSS Range Filter
        layout.addWidget(QLabel("CVSS Range:"))
        self.cvss_min = QSpinBox()
        self.cvss_min.setRange(0, 10)
        self.cvss_min.setValue(0)
        layout.addWidget(self.cvss_min)
        
        layout.addWidget(QLabel("-"))
        self.cvss_max = QSpinBox()
        self.cvss_max.setRange(0, 10)
        self.cvss_max.setValue(10)
        layout.addWidget(self.cvss_max)
        
        # Organization Filter
        layout.addWidget(QLabel("Organization:"))
        self.org_filter = QComboBox()
        self.org_filter.addItem("All Organizations")
        layout.addWidget(self.org_filter)
        
        # Country Filter
        layout.addWidget(QLabel("Country:"))
        self.country_filter = QComboBox()
        self.country_filter.addItem("All Countries")
        layout.addWidget(self.country_filter)
        
        # Risk Level Filter
        layout.addWidget(QLabel("Risk Level:"))
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["All Risks", "High", "Medium", "Low"])
        layout.addWidget(self.risk_filter)
        
        # Apply Button
        apply_btn = QPushButton("Apply Filters")
        apply_btn.clicked.connect(self.emit_filters)
        layout.addWidget(apply_btn)
        
        layout.addStretch()
    
    def set_organizations(self, orgs: List[str]):
        """Update organization dropdown"""
        current = self.org_filter.currentText()
        self.org_filter.clear()
        self.org_filter.addItem("All Organizations")
        self.org_filter.addItems(sorted(set(orgs)))
        if current in [self.org_filter.itemText(i) for i in range(self.org_filter.count())]:
            self.org_filter.setCurrentText(current)
    
    def set_countries(self, countries: List[str]):
        """Update country dropdown"""
        current = self.country_filter.currentText()
        self.country_filter.clear()
        self.country_filter.addItem("All Countries")
        self.country_filter.addItems(sorted(set(countries)))
        if current in [self.country_filter.itemText(i) for i in range(self.country_filter.count())]:
            self.country_filter.setCurrentText(current)
    
    def get_filters(self) -> Dict:
        """Get current filter values"""
        return {
            "cvss_min": self.cvss_min.value(),
            "cvss_max": self.cvss_max.value(),
            "organization": self.org_filter.currentText() if self.org_filter.currentText() != "All Organizations" else None,
            "country": self.country_filter.currentText() if self.country_filter.currentText() != "All Countries" else None,
            "risk_level": self.risk_filter.currentText() if self.risk_filter.currentText() != "All Risks" else None
        }
    
    def emit_filters(self):
        self.filters_changed.emit(self.get_filters())


class AnalyticsPanel(QWidget):
    """Advanced analytics visualization panel"""
    
    def __init__(self):
        super().__init__()
        self.engine = AnalyticsEngine()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create tabs for different analytics
        tabs = QTabWidget()
        
        # Top Vulnerable Organizations
        self.org_fig = Figure(figsize=(10, 5), dpi=100)
        self.org_canvas = FigureCanvas(self.org_fig)
        tabs.addTab(self.org_canvas, "Top Vulnerable Organizations")
        
        # Risk Trends
        self.trend_fig = Figure(figsize=(10, 5), dpi=100)
        self.trend_canvas = FigureCanvas(self.trend_fig)
        tabs.addTab(self.trend_canvas, "Risk Trends")
        
        # CVE Severity Distribution
        self.cve_fig = Figure(figsize=(10, 5), dpi=100)
        self.cve_canvas = FigureCanvas(self.cve_fig)
        tabs.addTab(self.cve_canvas, "CVE Severity Distribution")
        
        # Geographic Risk Distribution
        self.geo_fig = Figure(figsize=(10, 5), dpi=100)
        self.geo_canvas = FigureCanvas(self.geo_fig)
        tabs.addTab(self.geo_canvas, "Geographic Risk Distribution")
        
        layout.addWidget(tabs)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Analytics")
        refresh_btn.clicked.connect(self.refresh_all)
        layout.addWidget(refresh_btn)
    
    def refresh_all(self):
        """Refresh all analytics visualizations"""
        try:
            self.plot_top_vulnerable_orgs()
            self.plot_risk_trends()
            self.plot_cve_distribution()
            self.plot_geographic_distribution()
        except Exception as e:
            logger.error("Failed to refresh analytics: %s", e)
    
    def plot_top_vulnerable_orgs(self):
        """Plot top vulnerable organizations"""
        try:
            data = self.engine.get_top_vulnerable_organizations(limit=10)
            if not data:
                return
            
            self.org_fig.clear()
            ax = self.org_fig.add_subplot(111)
            
            orgs = [d["org"] for d in data]
            risks = [d["avg_risk"] for d in data]
            
            colors = ['#ff4444' if r >= 1.5 else '#ffaa44' if r >= 0.5 else '#44aa44' for r in risks]
            ax.barh(orgs, risks, color=colors)
            ax.set_xlabel("Average Risk Score")
            ax.set_title("Top 10 Most Vulnerable Organizations")
            ax.invert_yaxis()
            
            self.org_fig.tight_layout()
            self.org_canvas.draw()
        except Exception as e:
            logger.error("Failed to plot vulnerable organizations: %s", e)
    
    def plot_risk_trends(self):
        """Plot risk trends over time"""
        try:
            data = self.engine.get_risk_trends(days=30)
            if not data:
                return
            
            self.trend_fig.clear()
            ax = self.trend_fig.add_subplot(111)
            
            dates = list(data.keys())
            high = [data[d]["high"] for d in dates]
            medium = [data[d]["medium"] for d in dates]
            low = [data[d]["low"] for d in dates]
            
            ax.plot(dates, high, marker='o', label='High', color='#ff4444', linewidth=2)
            ax.plot(dates, medium, marker='s', label='Medium', color='#ffaa44', linewidth=2)
            ax.plot(dates, low, marker='^', label='Low', color='#44aa44', linewidth=2)
            
            ax.set_xlabel("Date")
            ax.set_ylabel("Device Count")
            ax.set_title("Risk Level Trends (Last 30 Days)")
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            self.trend_fig.autofmt_xdate()
            self.trend_fig.tight_layout()
            self.trend_canvas.draw()
        except Exception as e:
            logger.error("Failed to plot risk trends: %s", e)
    
    def plot_cve_distribution(self):
        """Plot CVE severity distribution"""
        try:
            data = self.engine.get_cve_severity_distribution()
            if not data:
                return
            
            self.cve_fig.clear()
            ax = self.cve_fig.add_subplot(111)
            
            labels = list(data.keys())
            sizes = list(data.values())
            colors = ['#ff4444', '#ff8844', '#ffaa44', '#44aa44', '#cccccc']
            
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax.set_title("CVE Severity Distribution")
            
            self.cve_fig.tight_layout()
            self.cve_canvas.draw()
        except Exception as e:
            logger.error("Failed to plot CVE distribution: %s", e)
    
    def plot_geographic_distribution(self):
        """Plot geographic risk distribution"""
        try:
            data = self.engine.get_geographic_risk_distribution()
            if not data:
                return
            
            self.geo_fig.clear()
            ax = self.geo_fig.add_subplot(111)
            
            countries = list(data.keys())[:15]  # Top 15 countries
            high_counts = [data[c]["high"] for c in countries]
            medium_counts = [data[c]["medium"] for c in countries]
            low_counts = [data[c]["low"] for c in countries]
            
            x = np.arange(len(countries))
            width = 0.25
            
            ax.bar(x - width, high_counts, width, label='High', color='#ff4444')
            ax.bar(x, medium_counts, width, label='Medium', color='#ffaa44')
            ax.bar(x + width, low_counts, width, label='Low', color='#44aa44')
            
            ax.set_xlabel("Country")
            ax.set_ylabel("Device Count")
            ax.set_title("Risk Distribution by Country (Top 15)")
            ax.set_xticks(x)
            ax.set_xticklabels(countries, rotation=45, ha='right')
            ax.legend()
            
            self.geo_fig.tight_layout()
            self.geo_canvas.draw()
        except Exception as e:
            logger.error("Failed to plot geographic distribution: %s", e)


class ExportManager:
    """Handle export functionality for reports"""
    
    @staticmethod
    def export_to_csv(devices: List[Device], filepath: str) -> bool:
        """Export device data to CSV"""
        try:
            data = []
            for device in devices:
                data.append({
                    'IP': device.ip,
                    'Organization': device.org,
                    'Country': device.country,
                    'Open Ports': device.num_open_ports,
                    'CVE Count': device.cve_count,
                    'Max CVSS': device.max_cvss,
                    'Risk Level': device.risk_label,
                    'Last Seen': device.last_seen
                })
            
            df = pd.DataFrame(data)
            df.to_csv(filepath, index=False)
            logger.info("Exported %d devices to %s", len(devices), filepath)
            return True
        except Exception as e:
            logger.error("Failed to export CSV: %s", e)
            return False
    
    @staticmethod
    def export_to_pdf(devices: List[Device], filepath: str) -> bool:
        """Export device data to PDF report"""
        try:
            # Create PDF with summary
            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            fig.suptitle('Threat Sentric AI - Threat Report', fontsize=16, fontweight='bold')
            
            # Risk Distribution
            risks = {"High": 0, "Medium": 0, "Low": 0}
            for device in devices:
                risk_str = str(device.risk_label).lower()
                if "2" in str(device.risk_label) or "high" in risk_str:
                    risks["High"] += 1
                elif "1" in str(device.risk_label) or "medium" in risk_str:
                    risks["Medium"] += 1
                else:
                    risks["Low"] += 1
            
            axes[0, 0].pie(risks.values(), labels=risks.keys(), autopct='%1.1f%%',
                          colors=['#ff4444', '#ffaa44', '#44aa44'])
            axes[0, 0].set_title("Risk Distribution")
            
            # CVSS Distribution
            cvss_data = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
            for device in devices:
                cvss = device.max_cvss or 0
                if cvss >= 9.0:
                    cvss_data["Critical"] += 1
                elif cvss >= 7.0:
                    cvss_data["High"] += 1
                elif cvss >= 4.0:
                    cvss_data["Medium"] += 1
                elif cvss > 0:
                    cvss_data["Low"] += 1
                else:
                    cvss_data["None"] += 1
            
            axes[0, 1].bar(cvss_data.keys(), cvss_data.values(), color=['#ff4444', '#ff8844', '#ffaa44', '#44aa44', '#cccccc'])
            axes[0, 1].set_title("CVSS Severity Distribution")
            axes[0, 1].tick_params(axis='x', rotation=45)
            
            # Top Countries
            countries = {}
            for device in devices:
                country = device.country or "Unknown"
                countries[country] = countries.get(country, 0) + 1
            
            top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]
            if top_countries:
                axes[1, 0].barh([c[0] for c in top_countries], [c[1] for c in top_countries])
                axes[1, 0].set_title("Top 10 Countries")
                axes[1, 0].set_xlabel("Device Count")
            
            # Summary Stats
            axes[1, 1].axis('off')
            summary_text = f"""
THREAT SUMMARY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total Devices: {len(devices)}
High Risk Devices: {risks['High']}
Medium Risk Devices: {risks['Medium']}
Low Risk Devices: {risks['Low']}

Average CVSS Score: {np.mean([d.max_cvss or 0 for d in devices]):.2f}
Devices with CVEs: {sum(1 for d in devices if d.cve_count and d.cve_count > 0)}

Total Open Ports: {sum(d.num_open_ports for d in devices if d.num_open_ports)}
Unique Organizations: {len(set(d.org for d in devices if d.org))}
Unique Countries: {len(set(d.country for d in devices if d.country))}
            """
            axes[1, 1].text(0.1, 0.5, summary_text, fontsize=10, family='monospace',
                           verticalalignment='center')
            
            fig.tight_layout()
            fig.savefig(filepath, format='pdf', dpi=150, bbox_inches='tight')
            logger.info("Exported PDF report to %s", filepath)
            return True
        except Exception as e:
            logger.error("Failed to export PDF: %s", e)
            return False


class ModelStatusWidget(QWidget):
    """Display model training status and information"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Model Status
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Model Status:"))
        self.status_label = QLabel("Loaded")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)
        
        # Last Training
        train_layout = QHBoxLayout()
        train_layout.addWidget(QLabel("Last Training:"))
        self.train_label = QLabel("N/A")
        train_layout.addWidget(self.train_label)
        train_layout.addStretch()
        layout.addLayout(train_layout)
        
        # Accuracy
        acc_layout = QHBoxLayout()
        acc_layout.addWidget(QLabel("Model Accuracy:"))
        self.acc_label = QLabel("N/A")
        acc_layout.addWidget(self.acc_label)
        acc_layout.addStretch()
        layout.addLayout(acc_layout)
        
        # Action Buttons
        button_layout = QHBoxLayout()
        retrain_btn = QPushButton("Retrain Model")
        retrain_btn.clicked.connect(self.on_retrain)
        button_layout.addWidget(retrain_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def on_retrain(self):
        from model.training_orchestrator import ModelTrainingOrchestrator
        try:
            orchestrator = ModelTrainingOrchestrator()
            if orchestrator.train_model():
                self.status_label.setText("Training Successful")
                self.status_label.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.status_label.setText("Training Failed")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
        except Exception as e:
            logger.error("Model retraining failed: %s", e)
            self.status_label.setText("Training Error")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")


class RemediationSuggestionsWidget(QWidget):
    """Display remediation suggestions for high-risk devices"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Recommended Actions:"))
        
        self.suggestions_table = QTableWidget()
        self.suggestions_table.setColumnCount(3)
        self.suggestions_table.setHorizontalHeaderLabels(["Risk Level", "Issue", "Remediation"])
        layout.addWidget(self.suggestions_table)
        
        refresh_btn = QPushButton("Generate Suggestions")
        refresh_btn.clicked.connect(self.refresh_suggestions)
        layout.addWidget(refresh_btn)
    
    def refresh_suggestions(self):
        """Generate remediation suggestions"""
        try:
            session = get_session()
            high_risk_devices = session.query(Device).filter(
                Device.risk_label == 2
            ).limit(10).all()
            
            suggestions = []
            for device in high_risk_devices:
                if device.max_cvss and device.max_cvss >= 9.0:
                    suggestions.append({
                        "risk": "Critical",
                        "issue": f"{device.ip}: Critical CVE (CVSS {device.max_cvss})",
                        "remediation": "1. Immediately isolate device from network\n2. Apply security patches\n3. Review access logs"
                    })
                elif device.num_open_ports and device.num_open_ports > 20:
                    suggestions.append({
                        "risk": "High",
                        "issue": f"{device.ip}: Excessive open ports ({device.num_open_ports})",
                        "remediation": "1. Close unnecessary ports\n2. Apply firewall rules\n3. Review services running"
                    })
            
            self.suggestions_table.setRowCount(len(suggestions))
            for i, sug in enumerate(suggestions):
                self.suggestions_table.setItem(i, 0, QTableWidgetItem(sug["risk"]))
                self.suggestions_table.setItem(i, 1, QTableWidgetItem(sug["issue"]))
                self.suggestions_table.setItem(i, 2, QTableWidgetItem(sug["remediation"]))
            
            session.close()
        except Exception as e:
            logger.error("Failed to generate suggestions: %s", e)
