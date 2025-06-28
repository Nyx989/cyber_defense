
# 🛡️ Enhanced Adaptive Cyber Defense System Using Behavioral Analysis

This project is a comprehensive, lightweight system designed to monitor user and system behavior to detect suspicious activity. It combines multiple background logging features and advanced behavior profiling techniques to identify anomalies that could indicate insider threats and provide robust protection against unauthorized activities.

-----

## 🔍 About the Project

The goal is to create a self-contained tool that runs silently in the background, continuously collecting data like keystrokes, clipboard access, screenshots, and detailed system and network activity. The system employs both **rule-based logic** and can be extended with **machine learning models** to flag unusual patterns (e.g., sudden changes in typing speed, frequent clipboard copying, or unusual network connections). When significant anomalies are detected, the system can send email alerts and, for high-risk events, potentially trigger automated responses like account disabling or network disconnection.

-----

## 🎯 Purpose of the System

The primary purpose of the **Enhanced Adaptive Cyber Defense System** is to provide a proactive and intelligent defense against **insider threats** and other unauthorized activities by continuously monitoring and analyzing user and system behavior.

Traditional security systems often rely on known signatures or rigid rules, which can miss novel attacks or subtle malicious actions from within an organization. This system fills that gap by:

  * **Establishing Baselines**: Learning and understanding "normal" user and system behavior through continuous data collection.
  * **Detecting Anomalies**: Identifying deviations from these established baselines that could signal suspicious or malicious intent. This includes unusual login times, atypical file access patterns, sudden changes in typing speed, or unauthorized network connections.
  * **Enabling Early Threat Detection**: By focusing on behavior, the system aims to catch threats in their nascent stages, potentially before they escalate into full-blown data breaches or system compromises.
  * **Providing Contextual Awareness**: Combining data from various sources (keystrokes, screenshots, network activity, etc.) to build a holistic picture of user actions, allowing for more informed and accurate threat assessments.
  * **Automating Responses**: Reducing the time between detection and mitigation by allowing for predefined automated actions, thus minimizing potential damage and strengthening the overall security posture.

In essence, this system transforms cybersecurity from a reactive process into a more **adaptive and predictive defense mechanism**, crucial for safeguarding sensitive data and maintaining system integrity in an evolving threat landscape.

-----

## ✅ Key Features

  * **Keystroke Logging**: Records keyboard input for detailed analysis of typing patterns and content.
  * **Clipboard Monitoring**: Tracks copy-paste activity to identify potential exfiltration of sensitive data.
  * **System Information Collection**: Gathers comprehensive machine details including CPU, RAM, OS information, and installed software.
  * **Network Monitoring**: Logs IP addresses, network packet data (using Scapy), and identifies geographic anomalies in access attempts.
  * **Screenshot Capturing**: Takes periodic or event-triggered screenshots for visual evidence of user activity.
  * **Audio Recording**: Captures ambient sound from the microphone to detect verbal instructions or threats.
  * **File Integrity Monitoring**: Checks if specific files or directories have been modified, accessed, or deleted.
  * **Behavioral Analysis**: Utilizes pre-defined rules and, optionally, machine learning models (TensorFlow/Scikit-learn) to detect anomalous behavior.
  * **Automated Response**: Triggers predefined actions like sending email alerts, or for critical events, can be configured for account disabling or network disconnection.
  * **Web Interface**: A simple Flask-based dashboard for real-time monitoring, viewing collected logs, system details, and behavior analysis.

-----

## 🧰 Tech Stack

  * **Primary Language**: Python
  * **Web Dashboard**: Flask
  * **Input & System Monitoring**: `pynput` (keystrokes), `pyperclip` (clipboard), `psutil` (system info)
  * **Audio Capture**: `sounddevice`
  * **Screenshots**: `Pillow`
  * **Network Packet Sniffing**: `Scapy`
  * **Email Alerts**: `SMTP` (configured for Gmail by default)
  * **Machine Learning (Optional)**: TensorFlow / Scikit-learn (for advanced anomaly detection)
  * **Database (Optional)**: MongoDB (for storing behavioral data and logs, if scaling is required beyond local file storage)
  * **Visualization (Optional)**: Dash or Grafana (for advanced reporting and dashboards)

-----

## 🛠️ Getting Started

### Prerequisites

Ensure you have Python installed. Then, install the necessary dependencies:

```bash
pip install -r requirements.txt
```

### Running the System

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/Enhanced-Cyber-Defense-System.git
    cd Enhanced-Cyber-Defense-System
    ```

    (Remember to replace `yourusername` with your actual GitHub username if you're hosting this project publicly.)

2.  **Set up the directory structure:**
    The system expects specific folders for logs and captured data. Ensure these directories exist:

    ```
    cyber_defense/
    ├── app.py
    ├── templates/
    ├── static/
    ├── screenshots/
    ├── logs/
    ├── audio/
    ├── keylogs/
    ├── clipboard_logs/
    ├── requirements.txt
    └── README.md
    ```

    *(Note: The provided folder structure implicitly covers `models/` if you implement ML, and the `logs/` directory will contain general system logs.)*

3.  **Configure Email Settings (Optional):**
    If you plan to use email alerts, open `app.py` (or `main.py` if you rename it) and configure your email credentials:

    ```python
    # Example in your main application file (e.g., app.py)
    EMAIL_ADDRESS = "your_email@gmail.com"
    EMAIL_PASSWORD = "your_email_app_password" # Use an app password for security!
    ```

    **Important**: For Gmail, you'll need to generate an **App Password** as regular passwords are not secure for direct application use.

4.  **Launch the system:**

    ```bash
    python app.py
    ```

    The system will start running locally in the background.

### Accessing the Dashboard

Open your web browser and navigate to:

```
http://localhost:5000/
```

From this dashboard, you can view collected logs, system details, and analyze behavioral data in real-time.

-----

## 🗂️ Project Structure

```
cyber_defense/
├── app.py                 # Main application logic and Flask dashboard
├── templates/             # HTML templates for the web interface
├── static/                # CSS, JS, and other static assets
├── screenshots/           # Directory to store captured screenshots
├── logs/                  # General system logs and activity logs
├── audio/                 # Directory to store captured audio snippets
├── keylogs/               # Directory for keystroke logs
├── clipboard_logs/        # Directory for clipboard activity logs
├── requirements.txt       # Python dependencies
└── README.md              # This project documentation
```

-----

## 🔒 Important Note on Usage & Ethical Considerations

This tool is strictly intended for **personal and research purposes only**.

  * **Legal Compliance**: Ensure full compliance with all local, national, and international privacy laws and regulations before deploying or using this system.
  * **Authorization**: **You must only use this system on devices and networks you own or have explicit, written permission to monitor.**
  * **Data Protection**: Implement robust data protection measures. Encrypt sensitive logs and restrict access to collected data to authorized personnel only.

**Disclaimer**: The developer of this project will not be held responsible for any misuse, illegal activities, or damages caused by the unauthorized deployment or use of this software. Users are solely responsible for ensuring their actions comply with all applicable laws and ethical guidelines.

-----

## 🙌 Credits

This system was built as a personal cybersecurity experiment to explore advanced behavioral monitoring techniques, inspired by real-world insider threat detection scenarios and the need for adaptive cyber defenses.

