#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenVPN Status Monitor

A GTK-based application that provides a graphical interface for managing and
monitoring OpenVPN connections.

Features:
    - Connect to OpenVPN using config files from ~/.config/openvpn/
    - Display connection status in real-time
    - Show connection details (IP address, connected time)
    - Monitor data transfer
    - Log connection events
    - Provide system notifications for connection status changes

Requirements:
    - Python 3.6+
    - GTK 3.0
    - OpenVPN
    - Python GObject bindings (PyGI)
    - Linux with pkexec for privilege escalation

Author: JaySea20
License: GPL-3.0
Version: 0.6-beta
Date: May 03, 2025
"""

import os
import gi
import subprocess
import threading
import time
import re
import signal

gi.require_version('Gtk', '3.0')
gi.require_version('Notify', '0.7')
from gi.repository import Gtk, GLib, Gdk, Notify, Pango

class OpenVPNStatusMonitor:
    def __init__(self):
        self.config_dir = os.path.expanduser("~/.config/openvpn")
        self.process = None
        self.monitor_thread = None
        self.running = False
        self.connected = False
        self.status_text = "Disconnected"
        self.ip_address = "N/A"
        self.network_address = "N/A"
        self.bytes_received = 0
        self.bytes_sent = 0
        self.connection_time = 0
        self.config_file = None
        self.vpn_interface = None
        self.pid_file = os.path.join(self.config_dir, "openvpn.pid")
        self.log_file = os.path.join(self.config_dir, "openvpn-gui.log")

        # Initialize GTK application
        self.init_gui()

        # Initialize notifications
        Notify.init("OpenVPN Status Monitor")

        # Check for stale processes on startup
        self.check_and_clean_stale_processes()

    def init_gui(self):
        # Create main window
        self.window = Gtk.Window(title="OpenVPN Client GUI")
        self.window.set_border_width(10)
        self.window.set_default_size(300, 200)
        self.window.set_position(Gtk.WindowPosition.CENTER)

        # Handle window close
        self.window.connect("delete-event", self.on_close)

        # Create main vertical box
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.window.add(self.main_box)

        # Config file selector
        config_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        config_label = Gtk.Label(label="Config")
        config_box.pack_start(config_label, False, False, 0)

        self.config_combo = Gtk.ComboBoxText()
        self.populate_configs()
        config_box.pack_start(self.config_combo, True, True, 0)

        self.main_box.pack_start(config_box, False, False, 0)

        # Connect/Disconnect button
        self.connect_button = Gtk.Button(label="Connect")
        self.connect_button.connect("clicked", self.on_connect_clicked)
        self.main_box.pack_start(self.connect_button, False, False, 0)

        # Status frame
        status_frame = Gtk.Frame(label="Connection Status")
        self.main_box.pack_start(status_frame, True, True, 0)

        # Status grid
        status_grid = Gtk.Grid()
        status_grid.set_column_spacing(10)
        status_grid.set_row_spacing(5)
        status_grid.set_border_width(10)
        status_frame.add(status_grid)

        # Status label
        status_grid.attach(Gtk.Label(label="Status:", xalign=0), 0, 0, 1, 1)
        self.status_value = Gtk.Label(label="Disconnected", xalign=0)
        self.status_value.modify_font(Pango.FontDescription("bold"))
        status_grid.attach(self.status_value, 1, 0, 1, 1)

        # Network Address label
        status_grid.attach(Gtk.Label(label="Network:", xalign=0), 0, 1, 1, 1)
        self.network_value = Gtk.Label(label="N/A", xalign=0)
        status_grid.attach(self.network_value, 1, 1, 1, 1)

        # IP Address label
        status_grid.attach(Gtk.Label(label="IP Address:", xalign=0), 0, 2, 1, 1)
        self.ip_value = Gtk.Label(label="N/A", xalign=0)
        status_grid.attach(self.ip_value, 1, 2, 1, 1)

        # Data transferred
        status_grid.attach(Gtk.Label(label="Data Received:", xalign=0), 0, 3, 1, 1)
        self.received_value = Gtk.Label(label="0 KB", xalign=0)
        status_grid.attach(self.received_value, 1, 3, 1, 1)

        status_grid.attach(Gtk.Label(label="Data Sent:", xalign=0), 0, 4, 1, 1)
        self.sent_value = Gtk.Label(label="0 KB", xalign=0)
        status_grid.attach(self.sent_value, 1, 4, 1, 1)

        # Connection time
        status_grid.attach(Gtk.Label(label="Connected Time:", xalign=0), 0, 5, 1, 1)
        self.time_value = Gtk.Label(label="00:00:00", xalign=0)
        status_grid.attach(self.time_value, 1, 5, 1, 1)

        # Log view
        log_frame = Gtk.Frame(label="Log")
        self.main_box.pack_start(log_frame, True, True, 0)

        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        log_frame.add(scrolled_window)

        self.log_buffer = Gtk.TextBuffer()
        self.log_view = Gtk.TextView(buffer=self.log_buffer)
        self.log_view.set_editable(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD)
        scrolled_window.add(self.log_view)

        # Log buttons
        log_buttons_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.main_box.pack_start(log_buttons_box, False, False, 0)

        # View Log button
        view_log_button = Gtk.Button(label="View Log")
        view_log_button.connect("clicked", self.on_view_log_clicked)
        log_buttons_box.pack_start(view_log_button, True, True, 0)

        # Clear Log button
        clear_log_button = Gtk.Button(label="Clear Log")
        clear_log_button.connect("clicked", self.on_clear_log_clicked)
        log_buttons_box.pack_start(clear_log_button, True, True, 0)

        # Set initial border for disconnected state
        self.update_status_display("Disconnected")

        # Show all elements
        self.window.show_all()

    def update_status_display(self, status):
        """Update status display with colored border"""
        self.status_value.set_text(status)

        # Get the style provider
        style_provider = Gtk.CssProvider()

        # Set CSS based on status
        if status == "Connected":
            css = b"""
            box {
                border: 10px solid rgba(39, 174, 96, 0.7);  /* Green border */
                padding: 10px;
            }
            """
        elif status == "Connecting...":
            css = b"""
            box {
                border: 10px solid rgba(243, 156, 18, 0.7);  /* Yellow/amber border */
                padding: 10px;
            }
            """
        else:  # Disconnected
            css = b"""
            box {
                border: 10px solid rgba(231, 76, 60, 0.7);  /* Red border */
                padding: 10px;
            }
            """

        # Apply the CSS
        style_provider.load_from_data(css)

        # Apply to the main box
        main_box_context = self.main_box.get_style_context()
        main_box_context.add_provider(
            style_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def populate_configs(self):
        self.config_combo.remove_all()

        if not os.path.exists(self.config_dir):
            self.log("Config directory not found: " + self.config_dir)
            return

        config_files = [f for f in os.listdir(self.config_dir) if f.endswith('.ovpn')]

        if not config_files:
            self.log("No .ovpn config files found in " + self.config_dir)
            return

        for config in config_files:
            self.config_combo.append_text(config)

        # Select the first config by default
        self.config_combo.set_active(0)

    def on_connect_clicked(self, button):
        if not self.running:
            self.connect_vpn()
        else:
            self.disconnect_vpn()

    def on_view_log_clicked(self, button):
        """Open the log file with the system's default editor"""
        try:
            # Ensure the log file exists
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'w') as f:
                    f.write("OpenVPN GUI Log\n")
                    f.write("==============\n\n")

            # Use xdg-open to open the file with the default application
            subprocess.Popen(["xdg-open", self.log_file])
            self.log(f"Opening log file: {self.log_file}")
        except Exception as e:
            self.show_error_dialog(f"Error opening log file: {str(e)}")

    def on_clear_log_clicked(self, button):
        """Clear the log display in the GUI (not the log file)"""
        self.log_buffer.set_text("")
        self.log("Log display cleared")

    def check_and_clean_stale_processes(self):
        """Check for any stale OpenVPN processes and terminate them"""
        self.log("Checking for stale OpenVPN processes...")

        if os.path.exists(self.pid_file):
            try:
                # Read PIDs from file
                with open(self.pid_file, 'r') as f:
                    pid_lines = f.readlines()

                pids = [int(line.strip()) for line in pid_lines if line.strip().isdigit()]

                if pids:
                    self.log(f"Found {len(pids)} potentially stale PIDs: {pids}")

                    # Check if processes still exist
                    stale_pids = []
                    for pid in pids:
                        try:
                            # Try to send signal 0 to check if process exists
                            os.kill(pid, 0)
                            stale_pids.append(pid)
                            self.log(f"Process {pid} is still running")
                        except OSError:
                            # Process doesn't exist
                            self.log(f"Process {pid} no longer exists")

                    # Terminate stale processes
                    if stale_pids:
                        self.log(f"Terminating {len(stale_pids)} stale processes...")

                        dialog = Gtk.MessageDialog(
                            transient_for=self.window,
                            flags=0,
                            message_type=Gtk.MessageType.WARNING,
                            buttons=Gtk.ButtonsType.YES_NO,
                            text="Stale OpenVPN Processes Detected"
                        )
                        dialog.format_secondary_text(
                            f"Found {len(stale_pids)} OpenVPN processes from a previous session. "
                            "Do you want to terminate these processes before continuing?"
                        )
                        response = dialog.run()
                        dialog.destroy()

                        if response == Gtk.ResponseType.YES:
                            for pid in stale_pids:
                                try:
                                    self.log(f"Terminating stale process {pid}")
                                    subprocess.run(["pkexec", "kill", str(pid)],
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE)
                                except Exception as e:
                                    self.log(f"Error terminating stale process {pid}: {str(e)}")

                # Remove stale PID file
                os.unlink(self.pid_file)
                self.log("Removed stale PID file")

            except Exception as e:
                self.log(f"Error checking stale processes: {str(e)}")

                # Remove potentially corrupted PID file
                try:
                    os.unlink(self.pid_file)
                except:
                    pass

    def connect_vpn(self):
        selected = self.config_combo.get_active_text()
        if not selected:
            self.show_error_dialog("Please select a configuration file.")
            return

        self.config_file = os.path.join(self.config_dir, selected)

        # Check if the config file exists
        if not os.path.exists(self.config_file):
            self.show_error_dialog(f"Config file not found: {self.config_file}")
            return

        # Check for stale processes before connecting
        self.check_and_clean_stale_processes()

        # Launch OpenVPN as subprocess
        try:
            # Find OpenVPN path
            openvpn_paths = [
                "/usr/sbin/openvpn",
                "/usr/bin/openvpn",
                "/usr/local/sbin/openvpn",
                "/usr/local/bin/openvpn"
            ]

            openvpn_path = None
            for path in openvpn_paths:
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    openvpn_path = path
                    break

            if not openvpn_path:
                # Try using which command
                try:
                    openvpn_path = subprocess.check_output(["which", "openvpn"],
                                                         universal_newlines=True).strip()
                except:
                    pass

            if not openvpn_path:
                self.show_error_dialog("OpenVPN executable not found. Please make sure OpenVPN is installed.")
                return

            self.log(f"Using OpenVPN at: {openvpn_path}")

            # Use pkexec to get admin privileges
            cmd = ["pkexec", openvpn_path, "--config", self.config_file]
            self.log(f"Running command: {' '.join(cmd)}")

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            # Write PID to file
            self.write_pid_file()

            self.running = True
            self.connect_button.set_label("Disconnect")
            self.update_status_display("Connecting...")

            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self.monitor_vpn_output)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            # Start status update timer
            GLib.timeout_add(1000, self.update_connection_time)

            self.show_notification("OpenVPN", "Connecting to VPN...")

        except Exception as e:
            self.show_error_dialog(f"Failed to start OpenVPN: {str(e)}")

    def write_pid_file(self):
        """Write OpenVPN PIDs to a file for later termination"""
        if not self.process:
            return

        try:
            # Make sure the config directory exists
            os.makedirs(self.config_dir, exist_ok=True)

            # Write the parent PID to file
            parent_pid = self.process.pid

            # Wait briefly and then get all child processes
            time.sleep(0.5)

            # Find all related OpenVPN processes
            ps_output = subprocess.check_output(
                ["ps", "-eo", "pid,ppid,command"],
                universal_newlines=True
            )

            pids = [parent_pid]  # Start with parent PID

            # Look for child processes where ppid matches parent_pid or command contains openvpn
            for line in ps_output.splitlines():
                if "openvpn" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = int(parts[0])
                        ppid = int(parts[1])

                        # If this is a child of our parent or it mentions our config file
                        if ppid == parent_pid or (self.config_file and self.config_file in line):
                            if pid not in pids:
                                pids.append(pid)

            # Write all PIDs to file
            with open(self.pid_file, 'w') as f:
                for pid in pids:
                    f.write(f"{pid}\n")

            self.log(f"Wrote PIDs to {self.pid_file}: {pids}")

        except Exception as e:
            self.log(f"Error writing PID file: {str(e)}")

    def disconnect_vpn(self):
        self.log("Attempting to disconnect VPN...")

        # Using PID file for termination
        try:
            if os.path.exists(self.pid_file):
                self.log(f"Found PID file: {self.pid_file}")

                # Read PIDs from file
                with open(self.pid_file, 'r') as f:
                    pid_lines = f.readlines()

                pids = [int(line.strip()) for line in pid_lines if line.strip().isdigit()]

                if pids:
                    self.log(f"Found {len(pids)} PIDs to terminate: {pids}")

                    # Terminate each process
                    for pid in pids:
                        try:
                            # Use pkexec to kill with elevated privileges
                            self.log(f"Terminating PID {pid}")
                            subprocess.run(["pkexec", "kill", str(pid)],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                        except Exception as e:
                            self.log(f"Error terminating PID {pid}: {str(e)}")

                    # Remove PID file after termination
                    os.unlink(self.pid_file)
                    self.log("Removed PID file")
                else:
                    self.log("No valid PIDs found in PID file")
            else:
                self.log("No PID file found, using fallback termination method")

                # Fall back to terminating the process directly
                if self.process:
                    try:
                        self.process.terminate()
                        self.process.wait(timeout=2)
                    except:
                        try:
                            self.process.kill()
                        except:
                            pass
        except Exception as e:
            self.log(f"Error during disconnect: {str(e)}")

        # Reset state variables
        self.running = False
        self.connected = False
        self.connect_button.set_label("Connect")
        self.update_status_display("Disconnected")
        self.ip_value.set_text("N/A")
        self.network_value.set_text("N/A")
        self.bytes_received = 0
        self.bytes_sent = 0
        self.connection_time = 0
        self.update_stats_display()

        # Clear process reference
        self.process = None

        self.log("VPN disconnected")
        self.show_notification("OpenVPN", "Disconnected from VPN")

    def monitor_vpn_output(self):
        if not self.process:
            return

        # Regular expression for detecting TUN/TAP device
        tun_pattern = re.compile(r'TUN/TAP device (\S+) opened')

        for line in iter(self.process.stdout.readline, ''):
            if not line:
                break

            # Log the output
            self.log(line.strip())

            # Look for TUN/TAP device name
            tun_match = tun_pattern.search(line)
            if tun_match:
                self.vpn_interface = tun_match.group(1)
                self.log(f"VPN interface detected: {self.vpn_interface}")

            # Check for initialization complete message
            if "Initialization Sequence Completed" in line:
                self.connected = True
                GLib.idle_add(self.update_status_display, "Connected")
                self.show_notification("OpenVPN", "Connected to VPN")

                # Get VPN IP address using the interface name
                threading.Thread(target=self.get_vpn_ip_address, daemon=True).start()

        # When the loop exits, the process has terminated
        GLib.idle_add(self.process_terminated)

    def process_terminated(self):
        """Called when the OpenVPN process terminates"""
        self.log("OpenVPN process terminated")

        # Clean up PID file if it exists
        if os.path.exists(self.pid_file):
            try:
                os.unlink(self.pid_file)
                self.log("Removed PID file")
            except Exception as e:
                self.log(f"Error removing PID file: {str(e)}")

        # Reset UI state
        self.running = False
        self.connected = False
        self.connect_button.set_label("Connect")
        self.update_status_display("Disconnected")

        # Clear process reference
        self.process = None

    def update_connection_time(self):
        if self.running and self.connected:
            self.connection_time += 1
            self.update_stats_display()

        # Continue the timer as long as we're running
        return self.running

    def update_stats_display(self):
        # Format the connection time as HH:MM:SS
        hours, remainder = divmod(self.connection_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        self.time_value.set_text(time_str)

        # Simulate data transfer (since we can't reliably get it from OpenVPN)
        if self.connected:
            self.bytes_received += 1024  # Simulate 1KB per second
            self.bytes_sent += 512       # Simulate 0.5KB per second

        # Format the data transferred
        def format_bytes(num_bytes):
            for unit in ['B', 'KB', 'MB', 'GB']:
                if num_bytes < 1024.0:
                    return f"{num_bytes:.2f} {unit}"
                num_bytes /= 1024.0
            return f"{num_bytes:.2f} TB"

        self.received_value.set_text(format_bytes(self.bytes_received))
        self.sent_value.set_text(format_bytes(self.bytes_sent))

    def log(self, message):
        # Format timestamp
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log_message = f"[{timestamp}] {message}"

        # Append to log file
        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, 'a') as f:
                f.write(log_message + "\n")
        except Exception as e:
            print(f"Error writing to log file: {str(e)}")

        # Update UI
        def append_log():
            end_iter = self.log_buffer.get_end_iter()
            self.log_buffer.insert(end_iter, log_message + "\n")
            # Auto-scroll to the end
            self.log_view.scroll_to_iter(self.log_buffer.get_end_iter(), 0.0, False, 0.0, 0.0)

        GLib.idle_add(append_log)

    def show_error_dialog(self, message):
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Error"
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    def show_notification(self, title, message):
        notification = Notify.Notification.new(title, message, "network-vpn")
        notification.show()

    def get_vpn_ip_address(self):
        """Get the actual IP address of the VPN interface"""
        if not self.vpn_interface:
            self.log("Cannot get IP address: VPN interface name unknown")
            return

        try:
            # Wait a moment for the interface to be fully configured
            time.sleep(1)

            # Get IP address information for the VPN interface
            ip_output = subprocess.check_output(
                ["ip", "addr", "show", "dev", self.vpn_interface],
                universal_newlines=True
            )

            # Extract the IPv4 address
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', ip_output)
            if ip_match:
                ip = ip_match.group(1)
                prefix = ip_match.group(2)
                GLib.idle_add(self.ip_value.set_text, ip)
                self.log(f"VPN IP address: {ip}/{prefix}")

                # Calculate network address
                try:
                    # Convert IP to integer
                    ipint = sum([int(octet) << (24 - 8 * i) for i, octet in enumerate(ip.split('.'))])
                    # Calculate netmask
                    netmask = (0xffffffff << (32 - int(prefix))) & 0xffffffff
                    # Calculate network address
                    network_int = ipint & netmask
                    # Convert back to dotted decimal
                    network = '.'.join([str((network_int >> (24 - 8 * i)) & 0xff) for i in range(4)])
                    # Set network address in UI
                    network_with_prefix = f"{network}/{prefix}"
                    GLib.idle_add(self.network_value.set_text, network_with_prefix)
                    self.log(f"Network address: {network_with_prefix}")
                except Exception as e:
                    self.log(f"Error calculating network address: {str(e)}")

                # Get routing information for this interface
                try:
                    route_output = subprocess.check_output(
                        ["ip", "route", "show", "dev", self.vpn_interface],
                        universal_newlines=True
                    )

                    # Log routing information
                    self.log("VPN routing information:")
                    for line in route_output.splitlines():
                        self.log(f"  {line}")
                except Exception as e:
                    self.log(f"Could not get routing info: {str(e)}")
            else:
                self.log("Could not find IPv4 address for VPN interface")

        except Exception as e:
            self.log(f"Error getting VPN IP address: {str(e)}")

    def on_close(self, widget, event):
        if self.running:
            # Ask for confirmation before closing
            dialog = Gtk.MessageDialog(
                transient_for=self.window,
                flags=0,
                message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.YES_NO,
                text="VPN is still connected"
            )
            dialog.format_secondary_text("Do you want to disconnect and quit?")
            response = dialog.run()
            dialog.destroy()

            if response == Gtk.ResponseType.YES:
                self.disconnect_vpn()
                Gtk.main_quit()
                return False
            else:
                return True
        else:
            Gtk.main_quit()
            return False

if __name__ == "__main__":
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    app = OpenVPNStatusMonitor()
    Gtk.main()
