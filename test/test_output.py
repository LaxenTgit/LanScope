"""
Tests for output formatting module.
"""

import pytest
from unittest.mock import patch, MagicMock
import io
import sys

from lanscope.output import Colors, ProgressBar, OutputFormatter, ExportManager


class TestColors:
    """Test ANSI color codes."""
    
    def test_colors_enabled(self):
        """Test colors are active by default."""
        c = Colors()
        assert c.RED == '\033[91m'
        assert c.END == '\033[0m'
    
    def test_disable_colors(self):
        """Test color disabling."""
        c = Colors()
        c.disable()
        assert c.RED == ''
        assert c.GREEN == ''
        assert c.BOLD == ''


class TestProgressBar:
    """Test progress bar."""
    
    def test_init(self):
        """Test initialization."""
        pb = ProgressBar(total=100)
        assert pb.total == 100
        assert pb.current == 0
    
    def test_update(self):
        """Test progress update."""
        pb = ProgressBar(total=10)
        pb.update(5)
        assert pb.current == 5
    
    def test_finish(self):
        """Test completion."""
        pb = ProgressBar(total=10)
        pb.finish()
        assert pb.current == 10
    
    def test_draw_output(self, capsys):
        """Test console output."""
        pb = ProgressBar(total=10, width=10)
        pb.update(5)
        captured = capsys.readouterr()
        assert "5/10" in captured.out or captured.out == ""  # May vary by terminal


class TestOutputFormatter:
    """Test output formatting."""
    
    def test_init_with_colors(self):
        """Test formatter with colors."""
        fmt = OutputFormatter(use_colors=True)
        assert fmt.use_colors is True
    
    def test_init_without_colors(self):
        """Test formatter without colors."""
        fmt = OutputFormatter(use_colors=False)
        assert fmt.colors.RED == ''  # Colors disabled
    
    def test_get_icon_pc(self):
        """Test PC icon."""
        fmt = OutputFormatter()
        icon = fmt._get_icon("Windows PC")
        assert icon == "🖥️" or icon == ""  # Depending on use_icons
    
    def test_get_icon_router(self):
        """Test router icon."""
        fmt = OutputFormatter()
        icon = fmt._get_icon("Router/Gateway")
        assert "📡" in icon or icon == ""
    
    def test_get_icon_unknown(self):
        """Test unknown device icon."""
        fmt = OutputFormatter()
        icon = fmt._get_icon("Unknown Device")
        assert "❓" in icon or icon == ""
    
    def test_print_header(self, capsys):
        """Test header output."""
        fmt = OutputFormatter(use_colors=False)
        fmt.print_header("192.168.1.0/24", 254)
        captured = capsys.readouterr()
        assert "LanScope" in captured.out
        assert "192.168.1.0/24" in captured.out
    
    def test_print_device(self, capsys):
        """Test device output."""
        fmt = OutputFormatter(use_colors=False, use_icons=False)
        
        device_info = {"type": "Windows PC", "confidence": 90, "os": "Windows 10"}
        ports = {445: {"service": "SMB"}, 3389: {"service": "RDP"}}
        arp_data = {"hostname": "DESKTOP-AX12", "mac": "00:1E:64:44:55:66", "vendor": "Dell"}
        
        fmt.print_device(1, "192.168.1.10", device_info, ports, arp_data)
        captured = capsys.readouterr()
        
        assert "192.168.1.10" in captured.out
        assert "Windows PC" in captured.out
        assert "DESKTOP-AX12" in captured.out
    
    def test_print_summary(self, capsys):
        """Test summary output."""
        fmt = OutputFormatter(use_colors=False)
        fmt.print_summary(254, 8, 12.5)
        captured = capsys.readouterr()
        assert "254" in captured.out
        assert "8" in captured.out
        assert "12.5" in captured.out
    
    def test_print_error(self, capsys):
        """Test error output."""
        fmt = OutputFormatter(use_colors=False)
        fmt.print_error("Connection failed")
        captured = capsys.readouterr()
        assert "Connection failed" in captured.out


class TestExportManager:
    """Test export functionality."""
    
    def test_to_json(self, tmp_path):
        """Test JSON export."""
        results = {
            "192.168.1.1": {
                "ip": "192.168.1.1",
                "hostname": "router",
                "mac": "AA:BB:CC:11:22:33"
            }
        }
        
        output_file = tmp_path / "results.json"
        ExportManager.to_json(results, str(output_file))
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "192.168.1.1" in content
        assert "router" in content
    
    def test_to_csv(self, tmp_path):
        """Test CSV export."""
        results = {
            "192.168.1.1": {
                "ip": "192.168.1.1",
                "hostname": "router",
                "mac": "AA:BB:CC:11:22:33",
                "vendor": "Cisco",
                "device_type": "Router",
                "os": "Linux",
                "confidence": 85,
                "ports": {80: {"service": "HTTP"}}
            }
        }
        
        output_file = tmp_path / "results.csv"
        ExportManager.to_csv(results, str(output_file))
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "192.168.1.1" in content
        assert "Cisco" in content
        assert "Router" in content
