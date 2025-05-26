# Basic Network Management System (NMS)

## Overview

This project is a basic Network Management System (NMS) designed to discover devices on a network using ICMP pings and collect fundamental information from them using SNMP (Simple Network Management Protocol). Discovered devices and their information are stored in a local JSON-based inventory. The system can be operated via a command-line interface (CLI) or a web interface.

## Features

*   **ICMP Ping Sweep:** Discovers active hosts on the specified network (available via CLI and Web).
*   **SNMP Data Collection:** Gathers basic system information from discovered devices, including:
    *   System Description (sysDescr)
    *   System Uptime (sysUpTime)
    *   System Name (sysName)
    *   System Location (sysLocation)
*   **JSON Inventory:** Stores device information in a `inventory.json` file.
*   **Command-Line Interface (CLI):** Provides commands to:
    *   Discover devices on a network.
    *   Show the current device inventory.
*   **Web Interface:** Provides a user-friendly way to:
    *   View the device inventory.
    *   Trigger device discovery on a network.
*   **Logging:** Outputs logs to both the console and a file (`nms.log`) for diagnostics and troubleshooting. Log levels are configurable.

## Prerequisites

*   **Python 3.x** (developed and tested with Python 3.10+).
*   **`ping` command:** The ICMP ping utility must be installed and accessible via the system's PATH. This is standard on most operating systems.
*   **(Optional) SNMP-enabled devices:** To collect SNMP data, target devices on your network must have SNMP enabled and configured (typically SNMPv1/v2c with a known community string).

## Setup & Installation

1.  **Clone the Repository (if applicable):**
    If you have access to the Git repository, clone it:
    ```bash
    git clone https://github.com/pluded/nms.git
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
    This will install `pysnmp` and `Flask`.

4.  **Install Development Dependencies (for running tests):**
    If you plan to run the unit tests, install the development dependencies:
    ```bash
    pip install -r requirements-dev.txt
    ```
    This will install `pytest` and `pytest-mock`.

## Usage

The NMS can be operated via a command-line interface (CLI) or a web interface. Ensure your virtual environment is activated.

### Command-Line Interface (CLI)

The main entry point for the CLI is `nms.cli`. Ensure you are in the project root directory.

*   **Show Help:**
    To see all available commands and options:
    ```bash
    python -m nms.cli --help
    ```

*   **Discover Devices (CLI):**
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

*   **Show Inventory (CLI):**
    Display the devices currently stored in the inventory.
    ```bash
    python -m nms.cli show
    ```

*   **Using a Custom Inventory File (CLI):**
    By default, the inventory is stored in `inventory.json` in the project root. You can specify a different file using the `--inventory-file` option with any CLI command.
    ```bash
    python -m nms.cli --inventory-file my_custom_inventory.json show
    ```

*   **Changing Log Level (CLI):**
    The default log level is `INFO`. You can change this for more detailed (e.g., `DEBUG`) or less detailed output.
    ```bash
    python -m nms.cli --log-level DEBUG discover 192.168.1.0/24
    ```
    Log output is written to `nms.log` (in the project root) and the console.

### Web Interface

The web interface provides a graphical way to interact with the NMS.

*   **Running the Web Interface:**
    To start the Flask development server, ensure you are in the project root directory and run:
    ```bash
    python -m nms.web.app
    ```
    The web server will typically be available at `http://0.0.0.0:5000/` or `http://localhost:5000/`. Check the console output for the exact URL.

*   **Available Web Pages:**
    *   **Home (`/`):** The main landing page.
    *   **View Inventory (`/inventory`):** Displays the devices currently stored in `inventory.json`.
    *   **Discover Devices (`/discover`):** Provides a form to input a network address and community string to trigger a new device discovery process. Results of the discovery are shown on the page.

    The web interface uses the same `inventory.json` file (by default, in the project root) and `nms.log` file as the CLI.

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
│   ├── discovery/          # Device discovery module (ICMP)
│   │   ├── __init__.py
│   │   └── icmp_sweeper.py
│   ├── inventory/          # Device inventory management
│   │   ├── __init__.py
│   │   └── device.py
│   ├── monitoring/         # SNMP data collection module
│   │   ├── __init__.py
│   │   └── snmp_collector.py
│   ├── utils/              # Utility modules
│   │   ├── __init__.py
│   │   └── logger.py
│   └── web/                # Flask web application
│       ├── __init__.py
│       ├── app.py          # Flask application logic
│       ├── templates/      # HTML templates
│       │   ├── index.html
│       │   ├── inventory.html
│       │   └── discover.html
│       └── static/         # Static files (CSS, JS - currently empty)
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
*   **Scheduled Scans:** Ability to schedule regular network discovery and data collection.
*   **Database Storage:** Using a database (e.g., SQLite, PostgreSQL) instead of JSON for more robust inventory management.
*   **Configuration File:** External configuration for SNMP communities, OIDs, etc.
*   **More Sophisticated Discovery:** Using techniques like ARP scanning or LLDP/CDP.
*   **Alerting:** Basic alerting for device status changes.
```
