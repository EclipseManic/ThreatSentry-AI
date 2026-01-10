# ThreatSentry AI: Enterprise-Grade AI-Powered Threat Hunting Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Framework](https://img.shields.io/badge/UI-PyQt5-green.svg)](https://www.qt.io/qt-for-python)
[![ML Stack](https://img.shields.io/badge/ML-Scikit--learn-orange.svg)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/Database-SQLAlchemy-blue.svg)](https://www.sqlalchemy.org/)

> Automate external asset discovery, intelligently enrich with multi-source data, and leverage ensemble machine learning to predict and prioritize risk. Transform alert fatigue into actionable intelligence.

## 🚀 Mission Statement

**ThreatSentry AI** eliminates security alert fatigue and enables proactive threat hunting through intelligent risk prioritization. It combines automated asset discovery, multi-source data enrichment, and advanced machine learning to transform raw security data into actionable intelligence.

---

## 👨‍💻 Author & Acknowledgments

**Project Lead:** EclipseManic

**Development Note:** This comprehensive enterprise security platform was architected and developed by a single developer with assistance from AI development tools for code generation, optimization, and documentation—demonstrating the viability of AI-augmented software engineering for complex systems.

---

## 📋 Executive Summary

Modern security teams face unprecedented challenges:
- **Alert Fatigue**: Thousands of daily alerts with signal-to-noise ratios making manual triage impossible
- **Fragmented Data**: Critical context scattered across SIEM, CMDB, patch systems, and network monitoring
- **Reactive Posture**: Responding to known threats rather than hunting for emerging risks
- **Resource Constraints**: Limited budgets and personnel in increasingly complex infrastructure

**ThreatSentry AI** solves these problems through:
1. **Automated External Asset Discovery** via Shodan API for continuous visibility
2. **Intelligent Multi-Source Enrichment** from NVD, internal systems, and behavioral analytics
3. **ML-Powered Risk Scoring** using ensemble models for accurate threat prioritization
4. **Executive-Ready Dashboards** for actionable intelligence and rapid response
5. **Proactive Alerting** that surfaces high-risk assets before incidents occur

---

## ✨ Core Features

### 🤖 Intelligent Risk Scoring Engine
- **Ensemble Machine Learning Model**: Combines Random Forest, Gradient Boosting, and Neural Networks for robust risk classification
- **Multi-Factor Analysis**: Evaluates 40+ security and business attributes beyond simple vulnerability counts:
  - **Temporal Context**: Exposure duration, patch lag, incident history
  - **Network Position**: Critical service status, network segment, firewall protection
  - **Behavioral Signals**: Authentication failures, traffic anomalies, false positive history
  - **Compliance Impact**: Data sensitivity, regulatory requirements, connected critical assets
- **Confidence Scoring**: Each prediction includes a confidence metric (0-1) for analysts to gauge reliability
- **Continuous Learning**: Model retrains automatically on configurable intervals with feedback integration

### 🌐 Automated Asset Discovery & Intelligence Fusion
- **Shodan Integration**: Continuous discovery of internet-facing devices with advanced query support
  - Preset queries for common scenarios (SSL certificates, RDP services, ICS/Modbus, etc.)
  - Custom query support for organization-specific asset hunting
- **NVD Enrichment**: Automatic CVE correlation using intelligent banner parsing
  - Banner service extraction supporting 14+ product types (Apache, Nginx, MySQL, IIS, etc.)
  - CVSS scoring and severity classification
  - Prevents data loss: Only updates CVE metrics when vulnerabilities are found
- **Internal Data Integration** (Extensible architecture for your environment):
  - **CMDB Collector**: Asset classification, criticality levels, compliance tags
  - **SIEM Collector**: Behavioral metrics, authentication patterns, anomaly scores
  - **Patch Management Collector**: Patch currency, missing updates, patch lag analysis
  - **Network Monitoring Collector**: Traffic patterns, DDoS detection, anomaly scores
- **Unified Database**: SQLite with 40+ indexed columns for efficient querying and reporting

### 📊 Executive Dashboard & Analysis Tools
- **PyQt5-Based GUI** with dark/light theme support:
  - Real-time risk distribution visualization (bar charts with Matplotlib)
  - Sortable, filterable device table with color-coded risk indicators
  - Quick-filter by Organization, Country, Risk Level
  - Auto-search across IP, Org, Country, Risk fields
- **Interactive Device Inspection**:
  - Detailed vulnerability list with CVSS scores
  - Vulnerability timeline and historical tracking
  - Risk factor breakdown explaining the scoring
- **Bulk Operations**:
  - Manual scan triggers (Shodan + NVD enrichment)
  - CSV/JSON data import with field validation
  - Model retraining with performance metrics
  - Manual alert sending to validate configurations
- **Analytics Panel** (Advanced):
  - Risk distribution trends
  - CVE impact analysis
  - Organization-wise vulnerability metrics

### 📧 Proactive Email Alerting
- **SendGrid Integration**: Automatic HTML email notifications for high-risk assets
  - Triggered immediately upon risk label change (Low/Medium → High)
  - Prevents duplicate alerts with "notified" status tracking
- **Rich Alert Content**:
  - Executive summary with risk score and confidence
  - Detailed vulnerability list (top N by CVSS)
  - Risk factor breakdown for security team context
  - Actionable remediation recommendations
- **Flexible Configuration**: Define alert recipients, email templates, and trigger conditions

#### Sample Alert Email
![Automated Security Alert Email Template]

[Gmail - Fwd_ Manual alert - Filtered (All) - 10 device(s) [duplicate alerts possible].pdf](https://github.com/user-attachments/files/24541015/Gmail.-.Fwd_.Manual.alert.-.Filtered.All.-.10.device.s.duplicate.alerts.possible.pdf)

*HTML formatted email with risk summary, CVE details, and remediation guidance sent via SendGrid*

### 📈 Model Transparency & Continuous Improvement
- **Performance Monitoring**:
  - Accuracy tracking across training epochs
  - Confusion matrix and classification reports
  - Feature importance analysis to understand model decisions
  - Data drift detection indicators
- **Feedback Loop**:
  - Manual risk label corrections by analysts
  - True positive/false positive tracking
  - Model weight adjustments based on feedback
  - Automated retraining schedule with metadata logging

### ⚡ Performance & Reliability
- **Optimized for Scale**:
  - Database indexing on 5+ columns for sub-millisecond queries
  - Result caching for frequently accessed data (28.7x speedup)
  - Pagination with "Load More" for large datasets (50 rows initial + 50 row increments)
  - Non-blocking UI with worker threads (QThread, ThreadPoolExecutor)
- **Robust Error Handling**:
  - Exponential backoff retry logic for API failures (Shodan, NVD, SendGrid)
  - Graceful degradation if optional services unavailable
  - Comprehensive logging with file rotation
  - Thread-safe signal/slot architecture prevents race conditions
- **Memory Efficient**:
  - Garbage collection after chart renders
  - Lazy-loaded UI tabs to reduce startup time
  - Session context managers ensure proper cleanup

---

## � Visual Overview

### Main Dashboard
![ThreatSentry AI Dashboard - Main Threat Hunting Interface]

<img width="1489" height="867" alt="Screenshot 2026-01-10 153154" src="https://github.com/user-attachments/assets/e10c7a66-8212-4748-9cfa-a767456c14b1" />

*Real-time risk visualization with sortable device table and risk distribution bar chart*

### Device Risk Assessment Table
![Device Table with Risk Indicators]

<img width="523" height="513" alt="image" src="https://github.com/user-attachments/assets/4825f015-c814-4e3c-80d1-a8e6181ba53f" />

*Sortable and filterable device listing with color-coded risk levels (Green=Low, Yellow=Medium, Red=High)*

### Analytics & Reporting Panel
![Analytics Tab - Risk Trends and CVE Analysis]

<img width="1494" height="651" alt="Screenshot 2026-01-10 153300" src="https://github.com/user-attachments/assets/1801484a-30e9-465a-8e1e-bc1187e67296" />

*Historical risk trends, vulnerability analysis, and organization-wise security metrics*

### Tools & Configuration
![Tools Tab - Model Status and Data Export]

<img width="1494" height="638" alt="Screenshot 2026-01-10 153240" src="https://github.com/user-attachments/assets/64a51a37-51d9-4af3-aec0-46073af11776" />

*Model training information, performance metrics, data export, and advanced filtering options*

### Email Alert Notifications
![Automated Security Alert Email]



*HTML formatted email with executive summary, vulnerability details, and remediation guidance*

### Manual Scan Workflow
![Scan Trigger Dialog]

<img width="505" height="152" alt="Screenshot 2026-01-10 153710" src="https://github.com/user-attachments/assets/7554cf9d-e2bc-4cc4-9602-885632e39820" />

*Execute Shodan + NVD enrichment with detailed error reporting and progress indication*

---

## �🛠️ Technology Stack

| Layer | Technologies |
|-------|---------------|
| **Backend** | Python 3.9+, SQLAlchemy ORM, APScheduler |
| **ML/AI** | Scikit-learn (Random Forest, Gradient Boosting, MLP), NumPy, Joblib |
| **Frontend** | PyQt5, Matplotlib, Custom theme manager |
| **Data** | Pandas, NumPy, SQLite3 |
| **APIs** | Shodan, NVDLib, SendGrid, Requests |
| **Utilities** | Python-dotenv, Logging module, Config management |

---

## 🏗️ Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      ThreatSentry AI                         │
├─────────────────────────────────────────────────────────────┤
│                      Scheduler (APScheduler)                  │
├──────────┬──────────────┬──────────────┬───────────┬─────────┤
│          │              │              │           │         │
▼          ▼              ▼              ▼           ▼         ▼
Shodan   NVD Lib      CMDB          SIEM        Patch    Network
Collector Collector   Collector    Collector   Mgmt     Monitor
                                                       
          │              │              │           │         │
          └──────────────┴──────────────┴───────────┴─────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │   SQLite DB     │
                  │  (40+ Columns)  │
                  └────────┬────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   Feature Engine    Model Training       Predictions
        │                 │                  │
        └─────────┬───────┴──────────┬──────┘
                  ▼                  ▼
          ┌──────────────────────┐
          │  Ensemble Model      │
          │  (RF + GB + MLP)     │
          └──────────┬───────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    PyQt5 GUI   Email Alerts   Analytics
```

### Data Processing Pipeline

1. **Discovery Phase** (Configurable interval, default 30 min)
   - Shodan scan with configurable queries
   - NVD enrichment with CVE correlation
   - Internal system enrichment for context

2. **Analysis Phase**
   - Feature engineering from 40+ attributes
   - Ensemble model prediction (Random Forest 40% + Gradient Boosting 40% + MLP 20%)
   - Risk label generation (0=Low, 1=Medium, 2=High)
   - Confidence scoring

3. **Alerting Phase**
   - Check for new high-risk assets
   - Generate and send email alerts via SendGrid
   - Update notification status

4. **Model Retraining** (Configurable interval, default 60 min)
   - Load all historical data
   - Extract features
   - Train ensemble with balanced class weights
   - Validate performance metrics
   - Save metadata for auditing

---

## 📋 Getting Started

### Prerequisites
- **Python**: 3.9 or later
- **API Keys** (required):
  - Shodan API key (https://www.shodan.io/)
  - SendGrid API key (https://sendgrid.com/) - for email alerts
- **Optional API Keys** (for enhanced enrichment):
  - CMDB endpoint and credentials
  - SIEM endpoint and credentials
  - Patch management system endpoint and credentials
  - Network monitoring endpoint and credentials

### Installation

#### Step 1: Clone Repository
```bash
git clone https://github.com/EclipseManic/ThreatSentry-AI.git
cd ThreatSentry-AI
```

#### Step 2: Create Virtual Environment
```bash
# On Windows
python -m venv .venv
.venv\Scripts\activate

# On macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Configure Environment
Create a `.env` file in the project root:
```bash
cp .env.example .env  # If provided, or create new
```

Edit `.env` with your credentials:
```ini
# Required - Threat Discovery
SHODAN_API_KEY=your_shodan_api_key_here
SHODAN_QUERY=                          # Leave empty to use presets
SHODAN_QUERY_EMPTY_TO_PRESET=True      # Use preset queries when SHODAN_QUERY is empty

# Optional - Email Alerts
SENDGRID_API_KEY=your_sendgrid_key_here
SENDER_EMAIL=alerts@yourcompany.com    # Must be verified in SendGrid
ALERT_RECIPIENTS=security@yourcompany.com,ciso@yourcompany.com

# Optional - Internal Enrichment (Implement in collectors/)
CMDB_API_ENDPOINT=https://cmdb.internal/api
CMDB_API_KEY=your_cmdb_key
SIEM_API_ENDPOINT=https://siem.internal/api
SIEM_API_KEY=your_siem_key

# Configuration
SCAN_INTERVAL_MINUTES=30               # How often to scan for new assets
RETRAIN_INTERVAL_MINUTES=60            # How often to retrain the model
MAX_SHODAN_RESULTS=50                  # Results per Shodan query
LOG_LEVEL=INFO                         # DEBUG, INFO, WARNING, ERROR

# Paths (Optional)
SQLITE_PATH=data/db/threat_sentric_ai.db
MODEL_PATH=data/models/rf_model.pkl
LOG_FILE_PATH=data/logs/threat_sentric_ai.log
```

#### Step 5: Initialize Database
```bash
python -c "from data import init_db; init_db()"
```

#### Step 6: Run the Application
```bash
python run.py
```

The dashboard will launch with the scheduler running in the background.

---

## 🚀 Usage Guide

### Dashboard Components Overview
![Dashboard Main Interface with All Tabs]
*Overview, Analytics, and Tools tabs for comprehensive threat assessment*

### 1. Device Table & Discovery
![Organization and Country Filters with Device List]
*Sortable device table with color-coded risk indicators (Green=Low, Yellow=Medium, Red=High)*
- **Color Coding**: Instant visual risk assessment
- **Sortable/Filterable**: Click column headers or use Quick Filter for rapid searching
- **Real-time Updates**: Dashboard refreshes as new threats detected

### 2. Risk Distribution Chart
![Risk Distribution Bar Chart]
*Overall security posture visualization with device counts per risk level*
- Shows count of devices across all risk categories
- Updates in real-time as model predictions change
- Identifies security hotspots requiring immediate attention

### 3. Key Action Buttons
- **Scan Now**: Manually trigger Shodan + NVD enrichment with detailed error reporting
- **Refresh**: Update dashboard from latest database state
- **Upload Data**: Bulk import CSV/JSON with device information
- **Train Model**: Manually retrain ensemble model with current data

### Advanced Features

#### Analytics Tab
![Analytics Panel - Risk Trends and Metrics]
- Detailed risk trends over time with historical analysis
- Top vulnerable services identification
- Organization-wise risk metrics and comparisons
- CVE impact analysis and vulnerability trending

#### Tools Tab
![Tools Panel - Model Status and Export
- Model status and training information


### Configuration

#### Preset Queries (Edit `core/config.py`)
```python
SHODAN_QUERIES = {
    "default": "product:apache",
    "web_apps": "http.title:\"login\" org:\"Your Company\"",
    "database": "port:27017 OR port:3306",
    "iot": "device:camera OR device:printer",
    "rdp": "port:3389",
    "vpn": "port:500 OR port:1194"
}
```

#### Custom Internal Collectors
Implement in `collectors/` directory:
1. Copy template from existing collector
2. Update `_collect()` method with your API calls
3. Return enrichment data
4. Register in scheduler (`core/scheduler.py`)

#### Email Alert Customization
Edit `alerts/email_alerts.py`:
- Modify HTML template for branded emails
- Add custom risk factor descriptions
- Adjust remediation recommendations

---

## 📊 Data Model

### Device Table (40+ Columns)
```
Core Identifiers:  ip, org, country, first_seen, last_seen
Vulnerability:     cve_count, max_cvss, vulnerabilities (rel)
Security Metrics:  auth_failures_24h, traffic_anomaly_score, patch_lag_days
Risk Assessment:   risk_label, risk_score, confidence_score
Context:          network_segment, service_category, is_critical_service
Compliance:       compliance_requirements, data_sensitivity_level
Historical:       incident_history_count, last_compromise_date, false_positive_count
Alerting:         notified, alert_history
```

### Vulnerability Table
```
Linked to Device:  device_id (FK)
CVE Info:         cve_id, cvss, summary
```

---

## 🔄 Workflow Examples

### Scenario 1: Daily Threat Hunting
1. Open dashboard → Review Risk=High devices (red)
2. Click device → View detailed CVE list
3. Note organization and infrastructure type
4. Cross-reference with SIEM for recent suspicious activities
5. Prioritize remediation based on criticality and patch lag

### Scenario 2: Incident Response
1. Received alert about new high-risk device
2. Dashboard shows vulnerability details and risk factors
3. Check Asset Management tab → See if device is known
4. Send manual alert to on-call SOC team
5. After remediation, dashboard auto-updates when Shodan reflects changes

### Scenario 3: Risk Reporting
1. Go to Analytics tab
2. Export risk distribution and trend charts
3. Identify organizational risk hotspots
4. Generate remediation roadmap
5. Track progress over time with periodic re-exports

---

## 🔧 Troubleshooting

### Common Issues

#### Issue: "Shodan API Key invalid" (403 Forbidden)
- **Solution**: Verify API key in SendGrid. Dashboard will show error but continue processing
- **Note**: NVD enrichment won't run (prevents data reset on API failures)

#### Issue: "No CVEs found for device"
- **Solution**: Check banner extraction. Edit `collectors/nvd_collector.py` keyword list
- **Prevention**: Manual enrichment via CSV upload to set CVE data manually

#### Issue: "Model confidence too low"
- **Solution**: Retrain with more labeled data. Provide feedback on misclassified devices
- **Prevention**: Use feedback system to improve training data quality

#### Issue: Email alerts not sending
- **Solution**: Verify SendGrid API key and sender email verified
- **Check**: `ENABLE_EMAIL_ALERTS` environment variable set to True

#### Issue: Database locked or slow queries
- **Solution**: Ensure indexes are created (init_db() does this)
- **Check**: No duplicate database connections (UI refresh only, not constant writing)

---

## 🛡️ Security Considerations

1. **API Key Management**: Use environment variables, never commit `.env` to Git
2. **Database Security**: SQLite suitable for single-user; migrate to PostgreSQL for multi-user
3. **Network Security**: Run on trusted network; implement network segmentation if exposing API
4. **Data Privacy**: Configure log rotation to limit disk space. Implement data retention policies
5. **Audit Logging**: All model decisions logged with feature values for auditability

---

## 📈 Performance Optimization Tips

| Issue | Solution |
|-------|----------|
| Slow dashboard load | Increase pagination size in config |
| High CPU during training | Reduce `n_estimators` in `model/advanced_model.py` |
| High memory usage | Enable logging cleanup, reduce chart resolution |
| Slow Shodan scans | Reduce `MAX_SHODAN_RESULTS`, use more specific queries |
| Slow NVD enrichment | Implement API caching, reduce product keyword extraction |

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas for enhancement:
- Additional collector implementations (Nessus, Tenable, Qualys integration)
- Web API for programmatic access
- Multi-user support with role-based access
- Advanced visualization (Grafana/ELK integration)
- Kubernetes deployment support

---

## 📄 License

This project is licensed under the MIT License—see [LICENSE](LICENSE) file for details.

---

## 📞 Support & Contact

- **Issues**: GitHub Issues for bug reports and feature requests
- **Documentation**: See [docs/](docs/) directory for detailed technical documentation
- **Email**: Maintainer information in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

## 🙏 Acknowledgments

- **Shodan**: For comprehensive internet-facing device discovery
- **NVD/NIST**: For authoritative vulnerability data
- **Scikit-learn**: Robust ML libraries and documentation
- **PyQt5**: Excellent GUI framework
- **Community**: All contributors and users providing feedback

---

**Made with ❤️ by EclipseManic | Securing Tomorrow's Infrastructure Today**

### 2. Create and activate a virtual environment
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### 3. Install required dependencies
```bash
pip install -r requirements.txt
```

---

## 🔐 Configuration

### 1. Environment Variables (`.env` file)
Create a `.env` file in the root directory with the following structure:

```bash
# --- Shodan API Key (Required) ---
SHODAN_API_KEY="YOUR_SHODAN_API_KEY"

# --- SendGrid Email Alerts (Required) ---
SENDGRID_API_KEY="YOUR_SENDGRID_API_KEY"
SENDER_EMAIL="your_verified_sender@example.com"
ALERT_RECIENTS="recipient1@example.com,recipient2@example.com"

# --- Database ---
SQLITE_PATH="threat_sentric_ai.db"

# --- Model ---
MODEL_PATH="threatsentry_model.pkl"

# --- Scheduler ---
SCAN_INTERVAL_MINUTES="30"
RETRAIN_INTERVAL_MINUTES="60"
RETRAIN_ON_SCHEDULE="True"

# --- Shodan Query Behavior Control ---
SHODAN_QUERY=""
SHODAN_QUERY_EMPTY_TO_PRESET="True"

# --- Logging ---
LOG_LEVEL="INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL

# --- Internal System Credentials (Optional - Add as needed for your collectors) ---
# CMDB_API_ENDPOINT="..."
# CMDB_API_KEY="..."
# SIEM_API_ENDPOINT="..."
# SIEM_API_KEY="..."
# PATCH_API_ENDPOINT="..."
# PATCH_API_KEY="..."
# NETWORK_MONITOR_ENDPOINT="..."
# NETWORK_MONITOR_KEY="..."
```

> The app loads environment variables via `os.getenv()` in `config.py`.  
> Never commit this file to version control.

---

## 🔍 Shodan Query Presets (`config.py`)

Modify the `SHODAN_QUERIES` dictionary to define your custom query presets:

```python
SHODAN_QUERIES = {
    "default": "product:apache",
    "org": 'org:"Your Company Name"',
    "net": 'net:"123.45.67.0/24"',
    "ssl": 'ssl:"yourcompany.com"',
    "hostname": 'hostname:".yourcompany.com"',
    "rdp": 'port:3389 "remote desktop"',
    "mongodb": 'port:27017 "mongodb"',
    "ics_modbus": 'port:502 "modbus"',
    "vuln_example": 'vuln:CVE-2024-12345',
    "http_login": 'http.title:"Login" org:"Your Company"'
}
```

If `SHODAN_QUERY` in `.env` is empty **and** `SHODAN_QUERY_EMPTY_TO_PRESET=True`,  
the scheduler will automatically cycle through these presets.

---

## 🧠 Implementing Internal Collectors

> ⚠️ **Important:** The internal collectors (`cmdb_collector.py`, `siem_collector.py`, `patch_collector.py`, `network_monitor_collector.py`) are **placeholders**.  
> Replace the placeholder logic with real integrations to your systems.

You’ll need to:
- Fetch internal data using APIs, databases, or SDKs.
- Map fetched data to the `Device` model attributes.
- Update the database session with this enriched information.

Without these integrations, the model will lack context for accurate predictions.

---

## 🧪 Running the Application

### (Optional) Generate Initial Training Data
```bash
python scripts/generate_realistic_training_data.py --count 1000
```
Creates `scripts/my_training_data.json`.  
You can upload this file through the GUI’s **Upload** option to initialize training data.

### Launch the Application
```bash
python run.py
```
The GUI will open and the scheduler will start scanning, enriching, and predicting automatically.

---

## ⚡ Quick Demo with Generated Data

1. Complete installation (steps 1–3).  
2. Set up your `.env` file (even with placeholder keys).  
3. Optionally adjust Shodan presets in `config.py`.  
4. Generate data:
   ```bash
   python scripts/generate_realistic_training_data.py --count 500
   ```
5. Launch the app:
   ```bash
   python run.py
   ```
6. In the GUI:
   - Select **Upload** → Choose `scripts/my_training_data.json`
   - Click **Refresh** to view populated device data and risk levels.

---

## 🛠️ Scripts and Usage Guide

| Script | Description |
|--------|--------------|
| **run.py** | Main entry point. Starts DB, scheduler, and GUI. |
| **scheduler.py** | Handles periodic scanning, enrichment, prediction, and retraining. |
| **scripts/generate_realistic_training_data.py** | Generates realistic training data for testing or bootstrapping. |
| **scripts/clear_db_enhanced.py** | Interactively clean database or reset notification flags. |
| **scripts/reset_db.py** | Completely resets the database. Use with caution. |

### Example Commands

```bash
# Generate 1000 records
python scripts/generate_realistic_training_data.py --count 1000

# View cleanup options
python scripts/clear_db_enhanced.py --help

# Delete all devices & vulnerabilities
python scripts/clear_db_enhanced.py --delete-devices --delete-vulns

# Reset notified flag
python scripts/clear_db_enhanced.py --reset-notified

# Dangerous full reset
python scripts/reset_db.py
```

---

## 💬 Feedback & Suggestions

This project was developed by **EclipseManic**.  
While code contributions are currently closed, your **feedback and bug reports** are highly appreciated.

Please open an [Issue](https://github.com/EclipseManic/ThreatSentry-AI/issues) to share your thoughts or report a problem.

---

## 📄 License

This project is licensed under the **MIT License**.  
See the [LICENSE](./LICENSE) file for details.
