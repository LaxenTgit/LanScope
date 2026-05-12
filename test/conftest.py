"""
Pytest fixtures and shared test utilities.
"""

import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def mock_socket():
    """Mock socket for network tests."""
    with patch('socket.socket') as mock:
        sock = Mock()
        sock.getsockname.return_value = ('192.168.1.50', 54321)
        sock.connect_ex.return_value = 0
        mock.return_value.__enter__ = Mock(return_value=sock)
        mock.return_value.__exit__ = Mock(return_value=False)
        yield mock


@pytest.fixture
def sample_arp_data():
    """Sample ARP scan result."""
    return {
        '192.168.1.1': {
            'mac': 'AA:BB:CC:11:22:33',
            'vendor': 'Cisco',
            'hostname': 'router.local'
        },
        '192.168.1.10': {
            'mac': '00:1E:64:44:55:66',
            'vendor': 'Dell Inc.',
            'hostname': 'DESKTOP-AX12'
        },
        '192.168.1.15': {
            'mac': '00:21:B7:77:88:99',
            'vendor': 'Apple Inc.',
            'hostname': 'MacBook-Pro.local'
        }
    }


@pytest.fixture
def sample_port_data():
    """Sample port scan result."""
    return {
        '192.168.1.1': {
            53: {'service': 'DNS', 'banner': None, 'state': 'open'},
            80: {'service': 'HTTP', 'banner': 'Server: nginx', 'state': 'open'},
            443: {'service': 'HTTPS', 'banner': None, 'state': 'open'},
            22: {'service': 'SSH', 'banner': 'SSH-2.0-OpenSSH_8.2', 'state': 'open'}
        },
        '192.168.1.10': {
            445: {'service': 'SMB', 'banner': None, 'state': 'open'},
            3389: {'service': 'RDP', 'banner': None, 'state': 'open'}
        }
    }


@pytest.fixture
def mock_platform_system():
    """Mock platform detection."""
    with patch('platform.system', return_value='Linux'):
        yield
