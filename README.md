# Basic Network Management System (NMS)

## Overview

This project is a basic Network Management System (NMS) designed to discover devices on a network using ICMP pings and collect fundamental information from them using SNMP (Simple Network Management Protocol). Discovered devices and their information are stored in a local JSON-based inventory. The system is operated via a command-line interface (CLI).

## Features

*   **ICMP Ping Sweep:** Discovers active hosts on the specified network.
*   **SNMP Data Collection:** Gathers basic system information from discovered devices, including:
    *   System Description (sysDescr)
    *   System Uptime (sysUpTime)
    *   System Name (sysName)
    *   System Location (sysLocation)
*   **JSON Inventory:** Stores device information in a `inventory.json` file.
*   **Command-Line Interface (CLI):** Provides commands to:
    *   Discover devices on a network.
    *   Show the current device inventory.
*   **Logging:** Outputs logs to both the console and a file (`nms.log`) for diagnostics and troubleshooting. Log levels are configurable.

## Prerequisites

*   **Python 3.x** (developed and tested with Python 3.10+).
*   **`ping` command:** The ICMP ping utility must be installed and accessible via the system's PATH. This is standard on most operating systems.
*   **(Optional) SNMP-enabled devices:** To collect SNMP data, target devices on your network must have SNMP enabled and configured (typically SNMPv1/v2c with a known community string).

## Setup & Installation

1.  **Clone the Repository (if applicable):**
    If you have access to the Git repository, clone it:
    ```bash
    git clone <repository_url>
    cd nms-project-root 
    ```
    (For the current context, assume you have the `nms` directory containing the project files.)

2.  **Create and Activate a Virtual Environment:**
    It's highly recommended to use a virtual environment to manage dependencies.
    ```bash
    python -m venv venv
    ```
    Activate the virtual environment:
    *   On macOS and Linux:
        ```bash
        source venv/bin/activate
        ```
    *   On Windows:
        ```bash
        .\venv\Scripts\activate
        ```

3.  **Install Dependencies:**
    Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    This will install `pysnmp`.

4.  **Install Development Dependencies (for running tests):**
    If you plan to run the unit tests, install the development dependencies:
    ```bash
    pip install -r requirements-dev.txt
    ```
    This will install `pytest` and `pytest-mock`.

## Usage

The NMS is operated via a command-line interface. Ensure your virtual environment is activated and you are in the directory containing the `nms` package (e.g., the project root if `nms` is a subdirectory, or inside `nms` if it's the main package directory).

The main entry point for the CLI is `nms.cli`.

*   **Show Help:**
    To see all available commands and options:
    ```bash
    python -m nms.cli --help
    ```

*   **Discover Devices:**
    Scan a network for active devices and attempt to collect SNMP information.
    ```bash
    python -m nms.cli discover <network_address_cidr> --community <snmp_community_string>
    ```
    *   `<network_address_cidr>`: The network to scan in CIDR notation (e.g., `192.168.1.0/24`).
    *   `--community <snmp_community_string>`: (Optional) The SNMP community string to use. Defaults to `public`.

    Example:
    ```bash
    python -m nms.cli discover 192.168.1.0/24 --community public
    ```

*   **Show Inventory:**
    Display the devices currently stored in the inventory.
    ```bash
    python -m nms.cli show
    ```

*   **Using a Custom Inventory File:**
    By default, the inventory is stored in `inventory.json`. You can specify a different file using the `--inventory-file` option with any command.
    ```bash
    python -m nms.cli --inventory-file my_custom_inventory.json show
    python -m nms.cli --inventory-file my_custom_inventory.json discover 10.0.0.0/24
    ```

*   **Changing Log Level:**
    The default log level is `INFO`. You can change this for more detailed (e.g., `DEBUG`) or less detailed output.
    ```bash
    python -m nms.cli --log-level DEBUG discover 192.168.1.0/24
    ```
    Log output is written to `nms.log` and the console.

## Running Tests

To run the unit tests, ensure you have installed the development dependencies (`requirements-dev.txt`). Navigate to the project root directory (the one containing the `nms` folder and `tests` folder) and run:
```bash
pytest
```
Or, to be more specific:
```bash
pytest tests/
```

## Project Structure

A simplified view of the project structure:

```
nms/
├── nms/                    # Main application package
│   ├── __init__.py         # Initializes the package, sets up logging
│   ├── cli.py              # Command-line interface logic
│   ├── discovery/          # Device discovery module
│   │   ├── __init__.py
│   │   └── icmp_sweeper.py # ICMP ping sweep implementation
│   ├── inventory/          # Device inventory management
│   │   ├── __init__.py
│   │   └── device.py       # Device and Inventory class definitions
│   ├── monitoring/         # SNMP data collection module
│   │   ├── __init__.py
│   │   └── snmp_collector.py # SNMP data fetching implementation
│   └── utils/              # Utility modules
│       ├── __init__.py
│       └── logger.py       # Logging configuration
├── tests/                  # Unit tests
│   ├── __init__.py
│   ├── discovery/
│   │   ├── __init__.py
│   │   └── test_icmp_sweeper.py
│   └── monitoring/
│       ├── __init__.py
│       └── test_snmp_collector.py
├── requirements.txt        # Main application dependencies
├── requirements-dev.txt    # Development/test dependencies
└── README.md               # This file
```

## Future Enhancements

This NMS is basic. Potential future enhancements could include:

*   **Broader SNMP Support:** Fetching more OIDs (e.g., interface details, CPU/memory usage). Support for SNMPv3.
*   **Web Interface:** A simple web UI to display inventory and trigger scans.
*   **Scheduled Scans:** Ability to schedule regular network discovery and data collection.
*   **Database Storage:** Using a database (e.g., SQLite, PostgreSQL) instead of JSON for more robust inventory management.
*   **Configuration File:** External configuration for SNMP communities, OIDs, etc.
*   **More Sophisticated Discovery:** Using techniques like ARP scanning or LLDP/CDP.
*   **Alerting:** Basic alerting for device status changes.
```
