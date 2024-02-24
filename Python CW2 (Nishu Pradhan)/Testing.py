import unittest
from unittest.mock import patch, Mock
from tkinter import Tk, ttk
import tkinter as tk
from scapy.all import Ether
import threading
from NetworkSniffer import NetworkSnifferApp

class TestPacketSnifferApp(unittest.TestCase):
    def setUp(self):
        self.root = Tk()
        self.app = NetworkSnifferApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_get_default_interface_windows(self):
        default_interface = self.app.get_default_interface()
        self.assertEqual(default_interface, "Wi-Fi")
    
    def test_display_welcome_message(self):
        # Mocking the Label creation and grid methods to avoid actual GUI updates
        with unittest.mock.patch.object(ttk, "Label") as mock_label:
            with unittest.mock.patch.object(mock_label.return_value, "grid") as mock_grid:
                self.app.display_welcome_message()

                # Assert that the Label constructor was called with the correct parameters
                mock_label.assert_called_once_with(self.app.root, text="Welcome to the Network Sniffing Tool!",
                                                   font=("Helvetica", 16), foreground="#3498db", background="#2c3e50")
                
                # Assert that the grid method was called with the correct parameters
                mock_grid.assert_called_once_with(row=0, column=0, columnspan=5, pady=20, sticky="we")

    @patch("platform.system", return_value="Linux")
    def test_get_default_interface_linux(self, mock_system):
        default_interface = self.app.get_default_interface()
        self.assertEqual(default_interface, "wlan0")

    @patch("tkinter.filedialog.asksaveasfilename", return_value="test_file.txt")
    @patch("builtins.open", create=True)
    @patch("tkinter.messagebox.showinfo")
    def test_save_packets(self, mock_showinfo, mock_open, mock_file_dialog):
        # Mocking file dialog, open, and showinfo functions for testing
        self.app.packet_queue.put("Test Packet Data")

        self.app.save_packets()

        mock_file_dialog.assert_called_once()
        mock_open.assert_called_once_with("test_file.txt", "a")
        mock_showinfo.assert_called_once_with("Save Packets", "Packets saved successfully!")

    def test_get_interfaces(self):
        interfaces = self.app.get_interfaces()
        self.assertEqual(interfaces, ["eth0", "eth1"])

    def test_update_interfaces(self):
        # Mocking the combobox configure method to avoid actual GUI updates
        with patch.object(self.app.root.children["!combobox"], "configure") as mock_configure:
            self.app.update_interfaces()
            mock_configure.assert_called_once()

    def custom_sniff_function(self, *args, **kwargs):
        # Create a list of mocked packets
        mock_packet = Mock()
        mock_packet.dst = "00:11:22:33:44:55"
        mock_packet.src = "66:77:88:99:aa:bb"
        mock_packet.type = 0x0800  # IP

        return [mock_packet]

        
if __name__ == "__main__":
    unittest.main()

