import pytest
import os
# Adjust sys.path to ensure 'nms' can be imported if tests are run from project root
# or if nms/ is not directly in PYTHONPATH.
import sys
# current_dir = os.path.dirname(os.path.abspath(__file__)) # nms/tests/web
# project_root = os.path.abspath(os.path.join(current_dir, '..', '..')) # nms/
# if project_root not in sys.path:
#    sys.path.insert(0, project_root)

# It's crucial that nms.web.app is imported AFTER any necessary path adjustments
# and AFTER pytest-flask might have done its own setup if it modifies app behavior.
# However, for pytest-flask, the app fixture is usually what you use.
from nms.web.app import app as flask_app # Rename to avoid conflict with pytest 'app' fixture
from nms.inventory.device import Inventory # Needed for mocking or creating dummy data

# Pytest-Flask provides the `client` fixture automatically.
# If not using pytest-flask, you'd define it like this:
# @pytest.fixture
# def client(app):
#     return app.test_client()

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Configure the app for testing
    flask_app.config.update({
        "TESTING": True,
        # "SECRET_KEY": "test_secret_key", # Set if your app uses sessions/flashing extensively
        # Define a temporary inventory file for testing if needed, or mock its path
        # For now, we'll assume DEFAULT_INVENTORY_FILE in app.py is used,
        # and we might need to manage or mock this file.
    })
    
    # Set a secret key for session-related functionality like flashing
    # This needs to be done before the first request in tests that use flashing.
    if not flask_app.secret_key:
        flask_app.secret_key = os.urandom(24)


    # If your app initializes things that shouldn't run during tests (e.g. global db connections),
    # you might need to modify app creation or use app factories.
    # For this app, the current structure of nms.web.app should be mostly fine.
    
    yield flask_app


# --- Basic Route Tests ---

def test_home_page(client):
    """Test GET request to the home page."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"Welcome to the NMS Web Interface!" in response.data
    assert b"Home" in response.data # Navigation link
    assert b"View Inventory" in response.data
    assert b"Discover Devices" in response.data

def test_inventory_page_get_no_file(client, tmp_path, monkeypatch):
    """Test GET request to inventory page when inventory.json does not exist."""
    # Ensure DEFAULT_INVENTORY_FILE points to a non-existent file in a temp path
    # This simulates the scenario where inventory.json hasn't been created yet.
    
    # We need to change where the app looks for inventory.json
    # app.config['DEFAULT_INVENTORY_FILE'] = str(tmp_path / "temp_inventory.json")
    # Or, more directly, mock DEFAULT_INVENTORY_FILE in nms.web.app
    # Note: flask_app.config is not directly used by the route for DEFAULT_INVENTORY_FILE path
    # The path is constructed using PROJECT_ROOT and "inventory.json"
    # So, we need to mock os.path.exists for the path used in the route.
    
    # Mock os.path.exists to return False for the specific inventory file path
    # The path is constructed in app.py as:
    # PROJECT_ROOT = os.path.abspath(os.path.join(app.root_path, '..', '..'))
    # DEFAULT_INVENTORY_FILE = os.path.join(PROJECT_ROOT, "inventory.json")
    
    # For simplicity, let's ensure the global DEFAULT_INVENTORY_FILE in nms.web.app
    # points to a temporary, non-existent file.
    original_inventory_file = flask_app.DEFAULT_INVENTORY_FILE
    temp_inventory_file = str(tmp_path / "non_existent_inventory.json")
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', temp_inventory_file)
    
    response = client.get('/inventory')
    assert response.status_code == 200
    assert b"Device Inventory" in response.data
    assert b"Inventory file (inventory.json) not found." in response.data
    
    # Restore original path if other tests depend on it, though fixtures should isolate.
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', original_inventory_file)


def test_inventory_page_get_with_data(client, tmp_path, monkeypatch):
    """Test GET request to inventory page with a dummy inventory.json."""
    dummy_inventory_content = {
        "192.168.1.1": {
            "ip_address": "192.168.1.1",
            "system_name": "TestDevice1",
            "system_description": "A test device",
            "uptime": "1 day", "location": None, "contact": None, "if_number": None,
            "other_attributes": {}
        }
    }
    # Create a temporary inventory file
    temp_inventory_file_path = tmp_path / "dummy_inventory.json"
    with open(temp_inventory_file_path, 'w') as f:
        import json
        json.dump(dummy_inventory_content, f)

    # Monkeypatch DEFAULT_INVENTORY_FILE in nms.web.app to use this temp file
    original_inventory_file = flask_app.DEFAULT_INVENTORY_FILE
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', str(temp_inventory_file_path))

    response = client.get('/inventory')
    assert response.status_code == 200
    assert b"Device Inventory" in response.data
    assert b"192.168.1.1" in response.data
    assert b"TestDevice1" in response.data
    assert b"A test device" in response.data
    assert b"error_message" not in response.data # Assuming error_message is None

    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', original_inventory_file)


def test_discover_page_get(client):
    """Test GET request to the discover page."""
    response = client.get('/discover')
    assert response.status_code == 200
    assert b"Discover Network Devices" in response.data
    assert b'name="network_address"' in response.data
    assert b'name="community_string"' in response.data
    assert b'type="submit"' in response.data


def test_discover_page_post_basic(client, mocker, tmp_path, monkeypatch):
    """Test POST request to discover page with mocks for backend functions."""
    # Ensure DEFAULT_INVENTORY_FILE points to a writable temp location
    # so inventory.save_to_json can be called without actual file system side effects
    # outside tmp_path, or we can mock save_to_json as well.
    temp_inventory_file = str(tmp_path / "test_inventory_during_discover.json")
    original_inventory_file = flask_app.DEFAULT_INVENTORY_FILE
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', temp_inventory_file)

    # Mock backend functions to prevent actual network operations
    mock_sweep = mocker.patch('nms.web.app.sweep_network', return_value=["10.0.0.1"])
    mock_fetch = mocker.patch('nms.web.app.fetch_snmp_data', return_value={
        "1.3.6.1.2.1.1.5.0": "MockedDeviceName" # sysName
    })
    # Mock save_to_json to prevent actual file writes if not using temp_inventory_file
    # For this test, we'll let it write to the temp_inventory_file to also implicitly
    # check that part of the code path, but a direct mock is also fine:
    mock_save = mocker.patch('nms.inventory.device.Inventory.save_to_json')


    form_data = {
        "network_address": "10.0.0.0/24",
        "community_string": "publictest"
    }
    response = client.post('/discover', data=form_data)

    assert response.status_code == 200 # Re-renders discover.html
    assert b"Discovery Log:" in response.data
    assert b"Starting discovery on network: 10.0.0.0/24" in response.data
    assert b"ICMP sweep found 1 active host(s): 10.0.0.1" in response.data
    assert b"Processing device: 10.0.0.1..." in response.data
    assert b"SNMP data for 10.0.0.1: system_name: MockedDeviceName" in response.data # Check for mapped attribute
    assert b"Updated inventory for 10.0.0.1 with SNMP data." in response.data
    assert b"Inventory saved to" in response.data # Check for inventory save message
    assert b"Discovery process completed successfully!" in response.data # Flashed message

    mock_sweep.assert_called_once_with("10.0.0.0/24")
    mock_fetch.assert_called_once_with("10.0.0.1", "publictest", flask_app.DEFAULT_SNMP_OIDS)
    mock_save.assert_called_once() # Inventory.save_to_json called

    # Restore original inventory file path
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', original_inventory_file)


def test_discover_page_post_invalid_cidr(client, mocker):
    """Test POST to discover with an invalid CIDR network address."""
    # No need to mock sweep/fetch as validation should fail first
    mock_sweep = mocker.patch('nms.web.app.sweep_network')

    form_data = {
        "network_address": "10.0.0.0/33", # Invalid CIDR
        "community_string": "public"
    }
    response = client.post('/discover', data=form_data)
    
    assert response.status_code == 200 # Re-renders discover.html
    assert b"Invalid network address format: 10.0.0.0/33" in response.data # Flashed error
    mock_sweep.assert_not_called()


def test_discover_page_post_ping_not_found(client, mocker, tmp_path, monkeypatch):
    """Test POST to discover when ping command is not found."""
    temp_inventory_file = str(tmp_path / "test_inventory_ping_not_found.json")
    original_inventory_file = flask_app.DEFAULT_INVENTORY_FILE
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', temp_inventory_file)

    # Import PingCommandNotFound from the correct module used in app.py
    from nms.discovery.icmp_sweeper import PingCommandNotFound
    mock_sweep = mocker.patch('nms.web.app.sweep_network', side_effect=PingCommandNotFound("Ping not found"))
    mock_fetch = mocker.patch('nms.web.app.fetch_snmp_data') # Should not be called

    form_data = {
        "network_address": "192.168.5.0/24",
        "community_string": "public"
    }
    response = client.post('/discover', data=form_data)

    assert response.status_code == 200 # Re-renders discover.html
    assert b"Ping command not found on the server. Cannot perform discovery." in response.data # Flashed error
    mock_sweep.assert_called_once_with("192.168.5.0/24")
    mock_fetch.assert_not_called()
    
    monkeypatch.setattr('nms.web.app.DEFAULT_INVENTORY_FILE', original_inventory_file)

# Note: To run these tests, ensure pytest, pytest-flask, and pytest-mock are installed.
# Execute `pytest nms/tests/web/test_app.py` from the project root.
# Ensure that the nms package (project root) is in PYTHONPATH.
# The `client` fixture is provided by `pytest-flask`.
# The `app` fixture is defined here to ensure Flask app is configured for testing.
# The `mocker` fixture is provided by `pytest-mock`.
# `tmp_path` and `monkeypatch` are standard pytest fixtures.
