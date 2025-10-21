# ThreatSentry AI: AI-Powered Threat Hunting Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Framework](https://img.shields.io/badge/UI-PyQt5-green.svg)](https://www.qt.io/qt-for-python)
[![ML Libraries](https://img.shields.io/badge/ML-Scikit--learn-orange.svg)](https://scikit-learn.org/)

## 👤 Author & Acknowledgment

This project was conceptualized and developed by **EclipseManic**.

AI development tools were utilized to assist in code generation, documentation, and refinement, enabling a single developer to build a comprehensive and robust application.

## 📖 Overview

In today's complex cybersecurity landscape, security teams are often overwhelmed by a flood of alerts and data from disparate systems. This "alert fatigue" leads to a reactive security posture, where analysts are constantly chasing threats rather than getting ahead of them.

**ThreatSentry AI** transforms this paradigm by providing a proactive, AI-driven threat hunting platform. It automates the lifecycle of threat discovery and risk assessment, starting with identifying external-facing assets via Shodan. It then enriches these assets with vulnerability data from the NVD and crucial context from internal systems (like CMDB, SIEM, patch management, and network monitoring). Most importantly, it uses a sophisticated machine learning model to **predict and prioritize risk** based on this comprehensive dataset. This allows security teams to focus their limited resources on the assets that pose the greatest threat, enabling intelligent and efficient threat hunting.

## ✨ Key Features

* **🤖 AI-Powered Risk Scoring**:
    * Utilizes an advanced **ensemble machine learning model** (Scikit-learn based: Random Forest, Gradient Boosting, MLP Neural Network) for accurate risk classification.
    * Generates a clear risk label (**Low, Medium, High**) and a confidence score for every discovered asset.
    * Leverages **advanced feature engineering**, incorporating data beyond basic vulnerabilities. It considers temporal patterns (`exposure_days`, `patch_lag_days`), network context (`network_segment`, `firewall_rules_count`), service context (`is_critical_service`, `data_sensitivity_level`), behavioral anomalies (`auth_failures_24h`, `traffic_anomaly_score`), and compliance requirements (`compliance_requirements`) to assess risk holistically.

* **🌐 Automated Asset Discovery & Multi-Source Enrichment**:
    * Integrates with the **Shodan API** to continuously discover internet-facing devices and services.
    * Automatically enriches discovered assets with vulnerability data from the **National Vulnerability Database (NVD)**, correlating services with known CVEs using improved banner parsing.
    * **Integrates with internal systems** (placeholders provided) to gather crucial context:
        * **CMDB Collector**: Adds asset context like network segment, criticality, compliance needs.
        * **SIEM Collector**: Gathers behavioral data like authentication failures.
        * **Patch Management Collector**: Determines patch lag days.
        * **Network Monitor Collector**: Provides traffic anomaly scores.
    * Stores all consolidated asset information in a centralized SQLite database.

* **🖥️ Intuitive Threat Dashboard**:
    * A clean and responsive Graphical User Interface (GUI) built with **PyQt5** provides a centralized view of all assets and their predicted risk posture.
    * Visualizes the overall risk distribution with an interactive bar chart (Matplotlib) and presents detailed information in a sortable, filterable, color-coded table.
    * Allows manual actions: trigger scans (Shodan + enrichment), upload asset data (CSV/JSON, now supporting advanced fields), initiate model retraining, and send manual email alerts.

* **📧 Proactive Email Alerting**:
    * Automatically generates and sends **detailed HTML email alerts** via SendGrid for newly discovered high-risk devices (Risk Label = 2).
    * Alerts provide a clear summary, risk factors (including CVSS, open ports), and actionable remediation guidance to accelerate response.
    * Includes a "mark as notified" system (`notified` flag in DB) to prevent duplicate alerts for the same high-risk device.

* **📈 Model Monitoring & Feedback**:
    * Includes modules for monitoring model performance over time, detecting potential data drift, and checking model health.
    * Provides a feedback system allowing manual correction of risk labels, which can be used to adjust model weights and retrain the model for continuous improvement.

## 🛠️ Technologies Used

* **Backend:** Python 3.9+
* **GUI:** PyQt5
* **Machine Learning:** Scikit-learn (Random Forest, Gradient Boosting, MLP), NumPy, Joblib
* **Data Handling:** Pandas
* **Data Collection:** Shodan API (`shodan`), NVDLib (`nvdlib`), Requests (`requests`)
* **Database:** SQLite (via SQLAlchemy ORM)
* **Email Alerts:** SendGrid API (`sendgrid`)
* **Scheduling:** APScheduler (`apscheduler`)
* **Configuration:** Python Dotenv (`python-dotenv`)
* **Plotting:** Matplotlib, Plotly (for potential future use or specific charts)

## ⚙️ How It Works (Architecture)

The application operates in a continuous, cyclical workflow managed by the **Scheduler**:

1.  **Collect (External Scan)**: The **Shodan Collector** scans for internet-facing devices based on configured queries. Basic device information (IP, Org, Country, Ports, Banners) is saved or updated in the **SQLite database**.
2.  **Enrich (Vulnerabilities)**: The **NVD Collector** queries the National Vulnerability Database for CVEs related to services identified in the banners, updating the device's vulnerability list, `cve_count`, and `max_cvss` in the database.
3.  **Enrich (Internal Context)**: A series of **Internal Collectors** are triggered to add business and security context (*Note: These require implementation specific to your environment*):
    * **CMDB Collector**: Adds data like network segment, criticality, compliance needs.
    * **SIEM Collector**: Adds behavioral metrics like auth failures.
    * **Patch Collector**: Adds patch lag information.
    * **Network Monitor Collector**: Adds traffic anomaly scores.
4.  **Analyze & Predict**: The **Model Training Orchestrator** loads the fully enriched data from the database. The **Feature Engineer** transforms this data into a numerical feature set. The pre-trained **Ensemble Model** predicts a risk label (`risk_label`) and confidence score (`confidence_score`) for each device. These predictions are stored back in the database.
5.  **Visualize**: The **PyQt5 GUI** reads the latest data (including predictions) from the database and presents it to the user in an interactive dashboard.
6.  **Alert**: The **Scheduler** periodically checks for new high-risk devices (`risk_label == 2`) that haven't been notified (`notified == False`) and triggers the **Email Alerts** module to send notifications.
7.  **(Optional) Retrain**: Periodically (based on `RETRAIN_ON_SCHEDULE` and `RETRAIN_INTERVAL_MINUTES`), the **Scheduler** triggers the **Model Training Orchestrator** to retrain the ensemble model using the latest data in the database.

## 🚀 Getting Started

### Prerequisites

* Python 3.9+
* API Keys/Credentials for:
    * [Shodan](https://account.shodan.io/)
    * [SendGrid](https://sendgrid.com/) (with a verified sender email)
    * Your internal systems (CMDB, SIEM, Patch Management, Network Monitoring) - *You will need to implement the connection logic in the respective collector files.*

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/eclipsemanic/threatsentry-ai.git](https://github.com/eclipsemanic/threatsentry-ai.git)
    cd threatsentry-ai
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows:
    # venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate 
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure your environment variables:**
    Create a file named `.env` in the project's root directory. Copy the contents below and **populate it with your actual credentials and settings**:
    ```env
    # --- Shodan ---
    # Your Shodan API Key
    SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
    # Default Shodan query if none specified in GUI (optional, defaults used if empty)
    SHODAN_QUERY="product:apache" 
    # Key from SHODAN_QUERIES in config.py to use by default in GUI (optional)
    DEFAULT_SHODAN_QUERY_KEY="default"
    # Max results per Shodan scan
    MAX_SHODAN_RESULTS="50"

    # --- SendGrid Email Alerts ---
    # Your SendGrid API Key
    SENDGRID_API_KEY="YOUR_SENDGRID_API_KEY"
    # Verified sender email address in SendGrid
    SENDER_EMAIL="your_verified_sender@example.com"
    # Comma-separated list of recipient email addresses
    ALERT_RECIPIENTS="recipient1@example.com,recipient2@example.com"

    # --- Database ---
    # Path to the SQLite database file (will be created if it doesn't exist)
    SQLITE_PATH="threat_sentric_ai.db"

    # --- Model ---
    # Path where the trained machine learning model will be saved/loaded
    MODEL_PATH="threatsentry_model.pkl"

    # --- Scheduler ---
    # Interval (minutes) for running scans and enrichments
    SCAN_INTERVAL_MINUTES="30"
    # Interval (minutes) for retraining the model
    RETRAIN_INTERVAL_MINUTES="60"
    # Set to True to enable scheduled retraining, False to disable
    RETRAIN_ON_SCHEDULE="True"

    # --- Internal System Credentials (Add as needed for your collectors) ---
    # Example: CMDB_API_KEY="YOUR_CMDB_KEY"
    # Example: SIEM_API_ENDPOINT="https://your-siem-api/..."
    # Example: PATCH_SYSTEM_USER="patch_user"
    # Example: PATCH_SYSTEM_PASSWORD="patch_password" 
    ```
    *[Note: Add corresponding `os.getenv()` calls in `config.py` for any new credentials you add here, and use those config variables in your collector implementations.]*

5.  **Implement Internal Collectors:**
    * Open the files in the `collectors/` directory (`cmdb_collector.py`, `siem_collector.py`, `patch_collector.py`, `network_monitor_collector.py`).
    * Replace the placeholder comments and logic with actual code to connect to your specific internal systems (using appropriate libraries like `requests`, database connectors, or vendor-specific SDKs) and fetch the required data.
    * Ensure the fetched data is correctly mapped and updates the `Device` object attributes in the database session.

### Running the Application

1.  **(Optional) Generate Initial Training Data:** If you don't have existing data, you can generate a synthetic dataset (which now includes all advanced fields):
    ```bash
    python scripts/generate_realistic_training_data.py --count 1000 
    # (Adjust --count as needed)
    ```
    Then, upload the generated `scripts/my_training_data.json` file via the GUI's "Upload" action to populate the database and train an initial model.

2.  **Launch the Application:**
    Run the main `run.py` script from the project's root directory:
    ```bash
    python run.py
    ```
    The GUI window will appear. The scheduler will start its first cycle (Shodan scan, NVD lookup, internal enrichments, prediction) shortly after launch.

### 🛠️ Scripts and Usage Guide

This project contains several scripts for core functionality and maintenance:

* **`run.py`**: The main entry point. Initializes the database, starts the background scheduler (for scanning, enrichment, prediction, alerting, retraining), and launches the GUI.
* **`scheduler.py`**: Manages all automated background tasks based on intervals defined in `config.py`.
* **`scripts/generate_realistic_training_data.py`**: Generates a synthetic dataset (JSON format) including *all* basic and advanced features needed for bootstrapping or testing the model. Use the GUI's "Upload" feature to import this data.
    ```bash
    # Generate 1000 records (default output: scripts/my_training_data.json)
    python scripts/generate_realistic_training_data.py --count 1000
    ```
* **`scripts/clear_db_enhanced.py`**: Safely cleans up the database with interactive confirmations. Allows deleting devices, vulnerabilities, or just resetting the 'notified' flag.
    ```bash
    # See options
    python scripts/clear_db_enhanced.py --help 
    
    # Example: Delete all devices and vulns (will ask for confirmation)
    python scripts/clear_db_enhanced.py --delete-devices --delete-vulns
    
    # Example: Reset notification flags without deleting data (will ask for confirmation)
    python scripts/clear_db_enhanced.py --reset-notified
    ```
* **`scripts/reset_db.py`**: **DANGER:** Deletes the entire database file and re-initializes an empty schema. Use with caution!
    ```bash
    python scripts/reset_db.py 
    ```

## 💬 Feedback and Suggestions

This is a solo project developed by EclipseManic. While direct code contributions are not being accepted at this time, feedback, suggestions, and bug reports are highly appreciated.

Please feel free to open an issue on the GitHub repository to share your thoughts or report a problem.

## 📄 License

This project is distributed under the MIT License. See the `LICENSE` file for more information.
