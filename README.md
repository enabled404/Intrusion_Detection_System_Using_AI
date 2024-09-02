# Intrusion Detection System

This is a Python-based real-time Intrusion Detection System (IDS) designed for network monitoring and real time threat detection. The system captures and analyzes network packets and detects potential intrusions using a graphical user interface (GUI) built with Tkinter. It also integrates with several APIs for enhanced threat intelligence.

## Features

- **Packet Sniffing and Analysis**: Monitors and analyzes network traffic.
- **Real-Time Alerts**: Provides real-time notifications for potential intrusions.
- **API Integrations**:
  - **AbuseIPDB**: Checks suspicious IP addresses against the AbuseIPDB database.
  - **Gemini 1.5 Pro**: Integrates with the Gemini 1.5 Pro API for advanced threat detection.
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
