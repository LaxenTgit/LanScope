"""
Tests for device fingerprinting module.
"""

import pytest
from unittest.mock import patch

from lanscope.fingerprint import DeviceFingerprinter


class TestDeviceFingerprinter:
    """Test DeviceFingerprinter class."""
    
    def test_identify_windows_from_ports(self):
        """Test identifying Windows from port signature."""
        fp = DeviceFingerprinter()
        
        ports = {
            445: {'service': 'SMB', 'state': 'open'},
            3389: {'service': 'RDP', 'state': 'open'},
            135: {'service': 'MSRPC', 'state': 'open'}
        }
        
        result = fp.identify("192.168.1.10", ports)
        assert result["type"] == "Windows PC"
        assert result["confidence"] > 50
    
    def test_identify_linux_from_ports(self):
        """Test identifying Linux from port signature."""
        fp = DeviceFingerprinter()
        
        ports = {
            22: {'service': 'SSH', 'state': 'open'},
            80: {'service': 'HTTP', 'state': 'open'},
            443: {'service': 'HTTPS', 'state': 'open'}
        }
        
        result = fp.identify("192.168.1.20", ports)
        assert "Linux" in result["type"] or result["os"] == "Linux/Unix"
    
    def test_identify_from_mac_vendor(self):
        """Test vendor-based identification."""
        fp = DeviceFingerprinter()
        
        ports = {22: {'service': 'SSH', 'state': 'open'}}
        result = fp.identify("192.168.1.15", ports, mac_vendor="Apple Inc.")
        
        assert "Mac" in result["type"] or result["os"] == "macOS"
    
    def test_identify_from_hostname(self):
        """Test hostname-based identification."""
        fp = DeviceFingerprinter()
        
        ports = {22: {'service': 'SSH', 'state': 'open'}}
        result = fp.identify(
            "192.168.1.10", ports, 
            hostname="DESKTOP-AX12"
        )
        
        assert result["type"] == "Windows PC"
    
    def test_identify_macbook_hostname(self):
        """Test MacBook hostname detection."""
        fp = DeviceFingerprinter()
        
        ports = {22: {'service': 'SSH', 'state': 'open'}}
        result = fp.identify(
            "192.168.1.15", ports,
            hostname="MacBook-Pro.local"
        )
        
        assert "Mac" in result["type"]
    
    def test_identify_unknown(self):
        """Test unknown device fallback."""
        fp = DeviceFingerprinter()
        
        ports = {}
        result = fp.identify("192.168.1.99", ports)
        
        assert result["type"] == "Unknown Device"
        assert result["confidence"] == 0
    
    def test_guess_os_windows(self):
        """Test Windows OS guess."""
        fp = DeviceFingerprinter()
        os_guess = fp._guess_os({445, 3389, 135}, None)
        assert os_guess == "Windows"
    
    def test_guess_os_linux(self):
        """Test Linux OS guess."""
        fp = DeviceFingerprinter()
        os_guess = fp._guess_os({22, 80}, None)
        assert "Linux" in os_guess
    
    def test_guess_os_apple(self):
        """Test Apple OS guess."""
        fp = DeviceFingerprinter()
        os_guess = fp._guess_os({22, 62078}, "Apple Inc.")
        assert os_guess == "iOS"
    
    def test_web_server_signature(self):
        """Test web server identification."""
        fp = DeviceFingerprinter()
        
        ports = {
            80: {'service': 'HTTP', 'state': 'open'},
            443: {'service': 'HTTPS', 'state': 'open'},
            8080: {'service': 'HTTP-Proxy', 'state': 'open'}
        }
        
        result = fp.identify("192.168.1.5", ports)
        assert result["type"] == "Web Server"
    
    def test_router_signature(self):
        """Test router identification."""
        fp = DeviceFingerprinter()
        
        ports = {
            53: {'service': 'DNS', 'state': 'open'},
            80: {'service': 'HTTP', 'state': 'open'},
            443: {'service': 'HTTPS', 'state': 'open'}
        }
        
        result = fp.identify("192.168.1.1", ports)
        assert result["type"] == "Router/Gateway"


class TestFingerprintDB:
    """Test FingerprintDB class."""
    
    def test_load_custom_signatures(self, tmp_path):
        """Test loading custom fingerprint database."""
        from lanscope.fingerprint import FingerprintDB
        
        db_file = tmp_path / "fingerprints.json"
        db_file.write_text('{"custom_device": {"ports": [80, 443]}}')
        
        db = FingerprintDB(str(db_file))
        assert db.signatures is not None
