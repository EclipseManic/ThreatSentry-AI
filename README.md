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

**ThreatSentry AI** transforms this paradigm by providing a proactive, AI-driven threat hunting platform. It automates the entire lifecycle of threat discovery, from identifying external-facing assets to enriching them with vulnerability data and, most importantly, using a sophisticated machine learning model to **predict and prioritize risk**. This allows security teams to focus their limited resources on the assets that pose the greatest threat to the organization, enabling them to hunt for threats intelligently and efficiently.

## ✨ Key Features

* **🤖 AI-Powered Risk Scoring**:
    * Utilizes an advanced **ensemble machine learning model** combining Random Forest, Gradient Boosting, and a Multi-Layer Perceptron (MLP) Neural Network for highly accurate risk classification.
    * Generates a clear risk label (**Low, Medium, High**) and a confidence score for every discovered asset.
    * Leverages **advanced feature engineering**, considering not just vulnerabilities but also temporal patterns, network context, and behavioral anomalies to assess risk holistically.

* **🌐 Automated Asset Discovery & Enrichment**:
    * Integrates with the **Shodan API** to continuously discover internet-facing devices and services.
    * Automatically enriches discovered assets with vulnerability data from the **National Vulnerability Database (NVD)**, correlating services with known CVEs.
    * Stores all asset information, including banners, open ports, and CVEs, in a centralized SQLite database.

* **🖥️ Intuitive Threat Dashboard**:
    * A clean and responsive Graphical User Interface (GUI) built with **PyQt5** provides a centralized view of all assets and their risk posture.
    * Visualize the overall risk distribution with an interactive bar chart and view detailed information in a sortable, color-coded table.
    * Allows for manual actions like triggering scans, uploading asset data (CSV/JSON), and initiating model retraining.

* **📧 Proactive Email Alerting**:
    * Automatically generates and sends **detailed HTML email alerts** via SendGrid for newly discovered high-risk devices.
    * Alerts provide a clear summary of the device, its risk factors, and actionable remediation guidance to accelerate response times.
    * Features a "mark as notified" system to prevent duplicate alerts for the same high-risk device.

## 🛠️ Technologies Used

* **Backend:** Python
* **GUI:** PyQt5
* **Machine Learning:** Scikit-learn, TensorFlow, XGBoost
* **Data Collection:** Shodan API, NVDLib
* **Database:** SQLite (via SQLAlchemy)
* **Email Alerts:** SendGrid API
* **Scheduling:** APScheduler


## ⚙️ How It Works (Architecture)

The application operates in a continuous, cyclical workflow:

1.  **Collect**: The **Scheduler** triggers the **Shodan Collector** to scan for devices based on a defined query.
2.  **Enrich**: The discovered devices are passed to the **NVD Collector**, which queries the NVD for relevant CVEs based on service banners and enriches the device data.
3.  **Store**: All collected and enriched data is saved to the **SQLite database**.
4.  **Analyze & Predict**: The **Model Training Orchestrator** loads the data, performs feature engineering, and uses the trained ensemble model to predict a risk label for each device. The results are stored back in the database.
5.  **Visualize**: The **PyQt5 GUI** reads the data from the database and presents it to the user in an interactive dashboard.
6.  **Alert**: The **Scheduler** periodically checks for new high-risk devices that have not been notified and triggers the **Email Alerts** module to send a notification to the security team.

## 🚀 Getting Started

### Prerequisites

* Python 3.9+
* API Keys for:
    * [Shodan](https://account.shodan.io/)
    * [SendGrid](https://sendgrid.com/) (with a verified sender email)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/eclipsemanic/ai-ml_threat_hunting_dashboard.git](https://github.com/eclipsemanic/ai-ml_threat_hunting_dashboard.git)
    cd ai-ml_threat_hunting_dashboard
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure your environment variables:**
    Create a file named `.env` in the project's root directory and populate it with your credentials:
    ```env
    # Shodan API Key
    SHODAN_API_KEY="your_shodan_api_key"

    # SendGrid API Key for Email Alerts
    SENDGRID_API_KEY="your_sendgrid_api_key"
    SENDER_EMAIL="your_verified_sender_email@example.com"
    ALERT_RECIPIENTS="recipient1@example.com,recipient2@example.com"

    # Path to the SQLite database file
    SQLITE_PATH="threathunt.db"

    # Path to the trained machine learning model file
    MODEL_PATH="rf_model.pkl"

    # Scheduler settings (in minutes)
    SCAN_INTERVAL_MINUTES="30"
    RETRAIN_INTERVAL_MINUTES="60"
    RETRAIN_ON_SCHEDULE=True

    MAX_SHODAN_RESULTS=50
    ```

### Running the Application

To launch the dashboard and start the background services, run the main `run.py` script:
```bash
python run.py
```
The GUI window will appear, and the scheduler will begin the first data collection cycle immediately.

### 🛠️ Scripts and Usage Guide
This project contains several scripts that handle everything from running the main application to managing the database and training the machine learning model.

### Core Application Scripts
run.py: This is the main entry point for the entire application. It initializes the database, starts the background scheduler, and launches the GUI.

scheduler.py: This script is responsible for all automated, background tasks. It is started by run.py and handles periodic scanning, model retraining, and alerting.

### Utility and Maintenance Scripts (scripts/)
scripts/generate_realistic_training_data.py: Generates a synthetic dataset to bootstrap the machine learning model.
```
# Generate 500 records (default)
python scripts/generate_realistic_training_data.py
# Generate 2000 records
python scripts/generate_realistic_training_data.py --count 2000
```
scripts/clear_db_enhanced.py: A safe and powerful script for database maintenance with interactive confirmations to prevent accidental data loss.

```
# Delete all devices and vulnerabilities after confirmation
python scripts/clear_db_enhanced.py --delete-devices --delete-vulns
# Reset the "notified" flag on all devices
python scripts/clear_db_enhanced.py --reset-notified
```

scripts/_email_preview.py: A helper script to preview the HTML email alert without sending an actual email.

### 💬 Feedback and Suggestions
This is a solo project developed by EclipseManic. While direct code contributions are not being accepted at this time, feedback, suggestions, and bug reports are highly appreciated.

Please feel free to open an issue to share your thoughts or report a problem.

### 📄 License
This project is distributed under the MIT License. See the LICENSE file for more information.
