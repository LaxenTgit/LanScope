"""
Tests for ARP scanning module.
"""

import pytest
from unittest.mock import patch, MagicMock, Mock

from lanscope.arp import ARPScanner, MACVendorDB


class TestARPScanner:
    """Test ARPScanner class."""
    
    def test_init_without_scapy(self):
        """Test initialization when scapy not available."""
        with patch('lanscope.arp.ARPScanner._check_scapy', return_value=False):
            scanner = ARPScanner()
            assert scanner._use_scapy is False
    
    def test_init_with_scapy(self):
        """Test initialization when scapy available."""
        with patch('lanscope.arp.ARPScanner._check_scapy', return_value=True):
            scanner = ARPScanner()
            assert scanner._use_scapy is True
    
    def test_scan_system_fallback(self):
        """Test system fallback scan (no scapy)."""
        scanner = ARPScanner()
        scanner._use_scapy = False
        
        with patch('subprocess.run') as mock_run:
            with patch('subprocess.check_output') as mock_output:
                # Mock ping output
                mock_run.return_value = Mock(returncode=0)
                # Mock arp table
                mock_output.return_value = """
? (192.168.1.1) at aa:bb:cc:11:22:33 on en0
? (192.168.1.10) at 00:1e:64:44:55:66 on en0
"""
                
                results = scanner._scan_system(["192.168.1.1", "192.168.1.10"])
                
                assert "192.168.1.1" in results
                assert results["192.168.1.1"]["mac"] == "aa:bb:cc:11:22:33"
    
    def test_lookup_vendor_known(self):
        """Test MAC vendor lookup with known OUI."""
        scanner = ARPScanner()
        vendor = scanner._lookup_vendor("00:21:B7:77:88:99")
        assert vendor == "Apple"
    
    def test_lookup_vendor_unknown(self):
        """Test MAC vendor lookup with unknown OUI."""
        scanner = ARPScanner()
        vendor = scanner._lookup_vendor("FF:FF:FF:FF:FF:FF")
        assert vendor == "Unknown"
    
    def test_resolve_hostname_success(self):
        """Test successful hostname resolution."""
        scanner = ARPScanner()
        with patch('socket.gethostbyaddr', return_value=("router.local", [], [])):
            hostname = scanner._resolve_hostname("192.168.1.1")
            assert hostname == "router.local"
    
    def test_resolve_hostname_failure(self):
        """Test failed hostname resolution."""
        scanner = ARPScanner()
        with patch('socket.gethostbyaddr', side_effect=Exception("Not found")):
            hostname = scanner._resolve_hostname("192.168.1.1")
            assert hostname is None
    
    def test_rate_limiting(self):
        """Test basic rate limiting."""
        import time
        scanner = ARPScanner()
        scanner.delay = 0.1
        
        start = time.time()
        scanner._rate_limit("example.com")
        scanner._rate_limit("example.com")
        elapsed = time.time() - start
        assert elapsed >= 0.1  # Should have delayed


class TestMACVendorDB:
    """Test MACVendorDB class."""
    
    def test_load_defaults(self):
        """Test loading default vendor DB."""
        db = MACVendorDB()
        assert db.lookup("00:21:B7:77:88:99") == "Apple Inc."
    
    def test_load_from_file(self, tmp_path):
        """Test loading custom vendor DB."""
        db_file = tmp_path / "vendors.json"
        db_file.write_text('{"001B11": "Custom Vendor"}')
        
        db = MACVendorDB(str(db_file))
        assert db.lookup("00:1B:11:22:33:44") == "Custom Vendor"
    
    def test_lookup_unknown(self):
        """Test unknown vendor."""
        db = MACVendorDB()
        assert db.lookup("FF:FF:FF:FF:FF:FF") is None
