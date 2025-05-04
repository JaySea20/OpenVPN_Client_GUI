# OpenVPN Client GUI

<div align="center">

![OpenVPN Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/f/f5/OpenVPN_logo.svg/320px-OpenVPN_logo.svg.png)

A lightweight, user-friendly graphical interface for managing OpenVPN connections on Linux systems

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/downloads/)
[![GTK 3.0](https://img.shields.io/badge/GTK-3.0-orange.svg)](https://www.gtk.org/)

</div>

## ✨ Features

- **Simple Interface** - Easy-to-use GUI for connecting to OpenVPN servers
- **Visual Status Indicators** - Color-coded borders show connection status at a glance
- **Connection Information** - View your VPN IP address, network, and connection time
- **Data Transfer Monitoring** - Track the amount of data sent and received
- **Configuration Selection** - Easily switch between different OpenVPN configurations
- **Detailed Logging** - View connection events and troubleshoot issues
- **System Integration** - Desktop notifications for connection status changes

## 📋 Requirements

- Python 3.6+
- GTK 3.0
- OpenVPN
- Python GObject bindings (PyGI)
- Linux with pkexec for privilege escalation

## 🚀 Installation

1. **Install Dependencies**
   ```bash
   sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-notify-0.7 openvpn
   ```

2. **Download the Application**
   ```bash
   git clone https://github.com/yourusername/openvpn-client-gui.git
   cd openvpn-client-gui
   ```

3. **Make Executable**
   ```bash
   chmod +x openvpn-status.py
   ```

4. **Create Desktop Entry** (optional)
   ```bash
   cp openvpn-status.desktop ~/.local/share/applications/
   sed -i "s|/home/USERNAME|$HOME|" ~/.local/share/applications/openvpn-status.desktop
   ```

## 📝 Usage

### Configuration Files

Place your OpenVPN configuration files (.ovpn) in the `~/.config/openvpn/` directory.

### Running the Application

Launch the application by running:
```bash
./openvpn-status.py
```

Or click on the desktop icon if you created one.

### Connecting to VPN

1. Select a configuration file from the dropdown menu
2. Click "Connect"
3. Enter your password when prompted (for sudo access)
4. The application will display connection status and details

### Connection Status

The application uses color-coded borders to indicate connection status:
- **Red** - Disconnected
- **Yellow** - Connecting
- **Green** - Connected

### Viewing Logs

The application keeps a detailed log of all operations:

- View real-time logs in the application window
- Click "Clear Log" to clear the log display in the application
- Click "View Log" to open the complete log file in your default text editor

## ❓ Troubleshooting

| Problem | Solution |
|---------|----------|
| Authentication Failed | Check your credentials in the OpenVPN configuration file |
| Connection Errors | Verify your internet connection and OpenVPN configuration |
| Permission Issues | Ensure pkexec is properly installed and configured |
| Stale Processes | The application will detect and offer to clean up any stale OpenVPN processes |

## 🔒 Security Considerations

- The application requires elevated privileges to establish VPN connections
- It uses pkexec to gain these privileges securely
- No passwords are stored by the application
- All credentials should be managed in your OpenVPN configuration files

## 📜 License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OpenVPN for the core VPN functionality
- GTK and PyGObject for the GUI framework

---

<div align="center">
Made with ❤️ for the open-source community
</div>
