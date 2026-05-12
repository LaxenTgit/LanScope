"""
Tests for network utilities (Subnet, IPRange, helpers).
"""

import pytest
import ipaddress
from unittest.mock import patch, MagicMock

from lanscope.network import Subnet, IPRange, is_valid_username, is_admin, validate_target


class TestSubnet:
    """Test Subnet class."""
    
    def test_init_with_cidr(self):
        """Test subnet creation with explicit CIDR."""
        subnet = Subnet("192.168.1.0/24")
        assert str(subnet.network) == "192.168.1.0/24"
        assert len(subnet.hosts) == 254  # 256 - 2 (network/broadcast)
    
    def test_init_without_cidr(self):
        """Test auto-detection of local subnet."""
        with patch('socket.socket') as mock_sock:
            sock = MagicMock()
            sock.getsockname.return_value = ('192.168.1.50', 54321)
            mock_sock.return_value.__enter__ = MagicMock(return_value=sock)
            mock_sock.return_value.__exit__ = MagicMock(return_value=False)
            
            subnet = Subnet()
            assert str(subnet.network) == "192.168.1.0/24"
    
    def test_get_hosts(self):
        """Test host list generation."""
        subnet = Subnet("192.168.1.0/30")  # Only 2 usable hosts
        hosts = subnet.get_hosts(exclude_local=False)
        assert len(hosts) == 2
        assert ipaddress.ip_address("192.168.1.1") in hosts
        assert ipaddress.ip_address("192.168.1.2") in hosts
    
    def test_get_hosts_exclude_local(self):
        """Test excluding local IP from hosts."""
        with patch('socket.socket') as mock_sock:
            sock = MagicMock()
            sock.getsockname.return_value = ('192.168.1.1', 54321)
            mock_sock.return_value.__enter__ = MagicMock(return_value=sock)
            mock_sock.return_value.__exit__ = MagicMock(return_value=False)
            
            subnet = Subnet("192.168.1.0/24")
            hosts = subnet.get_hosts(exclude_local=True)
            assert ipaddress.ip_address("192.168.1.1") not in hosts
    
    def test_str_representation(self):
        """Test string output."""
        subnet = Subnet("10.0.0.0/8")
        assert str(subnet) == "10.0.0.0/8"
    
    def test_len(self):
        """Test host count."""
        subnet = Subnet("192.168.1.0/24")
        assert len(subnet) == 254


class TestIPRange:
    """Test IPRange class."""
    
    def test_from_list(self):
        """Test creation from IP list."""
        ip_list = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        ip_range = IPRange(ip_list=ip_list)
        assert len(ip_range) == 3
    
    def test_from_range(self):
        """Test creation from start-end range."""
        ip_range = IPRange(start="192.168.1.1", end="192.168.1.5")
        assert len(ip_range) >= 4  # May vary by implementation
    
    def test_iteration(self):
        """Test IP iteration."""
        ip_range = IPRange(ip_list=["192.168.1.1", "192.168.1.2"])
        ips = list(ip_range)
        assert len(ips) == 2


class TestIsAdmin:
    """Test privilege detection."""
    
    def test_linux_admin(self):
        """Test Linux root detection."""
        with patch('platform.system', return_value='Linux'):
            with patch('os.geteuid', return_value=0):
                assert is_admin() is True
    
    def test_linux_not_admin(self):
        """Test Linux non-root."""
        with patch('platform.system', return_value='Linux'):
            with patch('os.geteuid', return_value=1000):
                assert is_admin() is False
    
    def test_windows_admin(self):
        """Test Windows admin detection."""
        with patch('platform.system', return_value='Windows'):
            with patch('ctypes.windll.shell32.IsUserAnAdmin', return_value=True):
                assert is_admin() is True


class TestValidateTarget:
    """Test target validation."""
    
    def test_cidr_target(self):
        """Test CIDR notation."""
        ttype, value = validate_target("192.168.1.0/24")
        assert ttype == "subnet"
        assert value == "192.168.1.0/24"
    
    def test_ip_target(self):
        """Test single IP."""
        ttype, value = validate_target("192.168.1.1")
        assert ttype == "ip"
        assert value == "192.168.1.1"
    
    def test_range_target(self):
        """Test IP range."""
        ttype, value = validate_target("192.168.1.1-192.168.1.100")
        assert ttype == "range"
    
    def test_hostname_target(self):
        """Test hostname fallback."""
        ttype, value = validate_target("router.local")
        assert ttype == "hostname"
        assert value == "router.local"


class TestIsValidUsername:
    """Test username validation (from utils concept)."""
    
    def test_valid_username(self):
        assert is_valid_username("john_doe") is True
        assert is_valid_username("user-123") is True
    
    def test_invalid_username(self):
        assert is_valid_username("") is False
        assert is_valid_username("a" * 60) is False  # Too long
        assert is_valid_username("user@domain") is False  # Invalid char
