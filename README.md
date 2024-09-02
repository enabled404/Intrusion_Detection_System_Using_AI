# Intrusion Detection System Implementing AI and LLMS

This is a Python-based real-time Intrusion Detection System (IDS) designed for network monitoring and real time threat detection. The system captures and analyzes network packets and detects potential intrusions using a graphical user interface (GUI) built with Tkinter. Utilized Scapy for packet capture and deep packet inspection (DPI) to analyze packet contents. Integrated a fine-tuned version of the Gemini 1.5 Pro API, providing unprecedented depth analysis and insights, a unique implementation globally. Incorporated threat intelligence from AbuseIPDB, IP geolocation from RapidAPI, and dynamic visualizations with Matplotlib. Features include real-time traffic monitoring, threat alerts, and email notifications for critical threats. This project stands out for its advanced integration of multiple detection techniques and its novel use of the LLM API.

## Features

- **Packet Sniffing and Analysis**: Monitors and analyzes network traffic.
- **Real-Time Alerts**: Provides real-time notifications for potential intrusions.
- **Deep Packet Inspection (DPI): Thoroughly examines packet contents to detect anomalies and threats.
- **Fine-Tuned Gemini 1.5 Pro API: Implements a unique, globally novel version for in-depth threat analysis.
- **Threat Intelligence Integration: Utilizes AbuseIPDB for IP reputation checks and RapidAPI for IP geolocation.
- **Dynamic Visualization: Displays real-time traffic data and detected threats using Matplotlib.
- **Customizable Alerts and Notifications: Sends email notifications for critical threats detected by the system.
- **User-Friendly Interface: Features a Tkinter-based GUI for easy interaction and monitoring.
- **Protocol and Type Detection: Accurately identifies and categorizes network protocols and packet types.
- **API Integrations**:
  - **AbuseIPDB**: Checks suspicious IP addresses against the AbuseIPDB database.
  - **Gemini 1.5 Pro**: Integrates with the Gemini 1.5 Pro API for advanced threat detection and analysis.
  - **GeoIP**: Determines the geographical location of IP addresses using the GeoIP service.

## How to Run

- **Operating System**: Kali Linux
- **Command**: `sudo python3 ids.py`

## Installation

1. **Ensure Python is Installed**:
    - This project requires Python 3. You can download it from [python.org](https://www.python.org/downloads/).

2. **Clone this repository**:
    ```bash
    git clone https://github.com/yourusername/Intrusion-Detection-System.git
    ```

3. **Navigate to the project directory**:
    ```bash
    cd Intrusion-Detection-System
    ```

4. **Install the required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```

5. **Set up the following API keys**:
    - **AbuseIPDB**: [Sign up](https://www.abuseipdb.com/register) to get an API key.
    - **Gemini 1.5 Pro**: Obtain the API key from the service provider.
    - **GeoIP**: If using MaxMind, [sign up](https://www.maxmind.com/en/geoip2-services-and-databases) to get an API key and database.

6. **Add your API keys to your environment**:
    ```bash
    export ABUSEIPDB_API_KEY=your_abuseipdb_api_key
    export GEMINI_API_KEY=your_gemini_api_key
    export GEOIP_API_KEY=your_geoip_api_key
    ```

7. **Run the IDS**:
    ```bash
    sudo python3 idslast5.py
    ```

## Requirements

Make sure you have the following installed:

- **Python 3**: [Download and install](https://www.python.org/downloads/)
- **Python Packages**:
  ```plaintext
  scapy
  requests
  tk
  geoip2
# Screenshots of its Working Interface
