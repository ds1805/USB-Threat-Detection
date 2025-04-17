import sys
import os
import json
import time
import logging
import socket
import threading
import smtplib
import wmi
import win32com.client
import pythoncom
import subprocess
import hashlib
import re
import magic  # pip install python-magic-bin for Windows
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("usb_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variables
connected_devices = {}
active_threats = {}

# Known malicious file signatures (MD5 hashes)
MALICIOUS_HASHES = {
    "e19ccf75ee54e06b06a5f33bd9dbc7d1": "Backdoor.Generic",
    "81feca5a8cd4466772babfeac3f1baea": "Trojan.Downloader",
    "1234567890abcdef1234567890abcdef": "Test.Malware.Sample",
    # Add more known malicious hashes here
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".js", 
    ".wsf", ".hta", ".dll", ".com", ".ps1", ".msi", ".reg"
]

# Suspicious file names or patterns
SUSPICIOUS_PATTERNS = [
    r"(backdoor|trojan|virus|hack|crack|keygen)",
    r"(autorun\.inf)",
    r"(system32|cmd\.exe|regedit\.exe)",
    r"(hidden\..+)",
]

# Maximum file size to scan (in bytes) - 50MB
MAX_SCAN_SIZE = 50 * 1024 * 1024

# Shutdown delay in seconds (3 secs)
SHUTDOWN_DELAY = 3

class ThreatScanner:
    def __init__(self, device_monitor=None):
        self.device_monitor = device_monitor
        self.mime_detector = magic.Magic(mime=True)
        
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    def is_file_suspicious(self, file_path, file_name):
        """Check if a file is suspicious based on various criteria."""
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > MAX_SCAN_SIZE:
                logger.info(f"Skipping large file: {file_path} ({file_size} bytes)")
                return False, ""
                
            # Check file extension
            _, ext = os.path.splitext(file_name.lower())
            if ext in SUSPICIOUS_EXTENSIONS:
                # Check MIME type to verify if the file is what it claims to be
                try:
                    mime_type = self.mime_detector.from_file(file_path)
                    # Executable file types
                    if "executable" in mime_type or "script" in mime_type:
                        return True, f"Suspicious executable file: {file_name} ({mime_type})"
                except:
                    # If MIME detection fails, consider it suspicious
                    return True, f"Suspicious file with unable to determine MIME type: {file_name}"
                
            # Check for suspicious patterns in filename
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, file_name.lower()):
                    return True, f"Suspicious filename pattern detected: {file_name}"
                    
            # Check if file is unusually small executable
            if ext in ['.exe', '.dll'] and file_size < 1024:
                return True, f"Suspicious small executable: {file_name} ({file_size} bytes)"
                
            # Check if file hash is known malicious
            file_hash = self.calculate_file_hash(file_path)
            if file_hash and file_hash in MALICIOUS_HASHES:
                threat_name = MALICIOUS_HASHES[file_hash]
                return True, f"Known malware detected: {threat_name} ({file_name})"
                
            # Check for autorun.inf file
            if file_name.lower() == "autorun.inf":
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read().lower()
                    if "open" in content or "shell" in content:
                        return True, f"Malicious autorun.inf file detected"
                
            return False, ""
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return False, ""
    
    def scan_directory(self, directory):
        """Scan directory for suspicious files."""
        threats = []
        
        try:
            # Only scan the root directory, not subfolders as per requirement
            files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
            for file_name in files:
                file_path = os.path.join(directory, file_name)
                
                is_threat, threat_info = self.is_file_suspicious(file_path, file_name)
                if is_threat:
                    threats.append({
                        "file_path": file_path,
                        "file_name": file_name,
                        "threat_info": threat_info
                    })
                    logger.warning(f"Threat detected: {threat_info} - Path: {file_path}")
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {str(e)}")
            
        return threats
            
    def scan_usb_drive(self, drive_letter):
        """Scan a USB drive for threats."""
        if not drive_letter or not os.path.exists(drive_letter):
            logger.error(f"Drive {drive_letter} does not exist")
            return []
            
        logger.info(f"Scanning USB drive {drive_letter} for threats...")
        return self.scan_directory(drive_letter)

class EmailSender:
    def __init__(self, config):
        self.config = config
        self.retry_count = 3
        self.retry_delay = 5
        
    def send(self, subject, message):
        if not all([self.config.get('smtp_server'), self.config.get('smtp_port'), 
                   self.config.get('username'), self.config.get('password'),
                   self.config.get('from_email'), self.config.get('to_email')]):
            logger.error("Email configuration incomplete")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = self.config['from_email']
        msg['To'] = self.config['to_email']
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))
        
        for attempt in range(self.retry_count):
            try:
                server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'], timeout=10)
                server.ehlo()
                server.starttls()
                server.login(self.config['username'], self.config['password'])
                server.sendmail(self.config['from_email'], self.config['to_email'], msg.as_string())
                server.quit()
                logger.info(f"Email sent: {subject}")
                return True
            except Exception as e:
                logger.error(f"Email attempt {attempt+1} failed: {str(e)}")
                if attempt < self.retry_count - 1:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"Failed to send email after {self.retry_count} attempts")
                    return False

class DeviceMonitor:
    def __init__(self, email_config):
        self.email_sender = EmailSender(email_config)
        self.hostname = socket.gethostname()
        self.ip_address = self.get_ip_address()
        self.lock = threading.Lock()
        self.running = False
        self.monitor_thread = None
        self.threat_scanner = ThreatScanner(self)
        
    def get_ip_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def execute_shutdown(self, device_id, drive_letter):
        """Execute system shutdown with no option to cancel."""
        logger.critical(f"Executing system shutdown due to threat on {drive_letter}")
        
        # Send a final email notification
        subject = f"CRITICAL: System shutting down - USB threat on {self.hostname}"
        message = f"SECURITY ALERT: Shutting down system due to threats detected on USB drive {drive_letter}\n\n"
        message += f"Host: {self.hostname} ({self.ip_address})\n"
        message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += f"System will shut down in {SHUTDOWN_DELAY} seconds."
        
        email_thread = threading.Thread(target=self.email_sender.send, args=(subject, message))
        email_thread.daemon = True
        email_thread.start()
        
        # Display a critical message before shutdown
        print(f"\n\n!!! CRITICAL SECURITY THREAT DETECTED !!!")
        print(f"Threats found on USB drive {drive_letter}")
        print(f"System will shut down in {SHUTDOWN_DELAY} seconds to prevent data compromise.")
        print("THIS ACTION CANNOT BE CANCELLED.")
        
        # Sleep for the shutdown delay before executing the actual shutdown
        time.sleep(SHUTDOWN_DELAY)
        
        # Execute unabortable shutdown
        try:
            # /f forces running applications to close
            # /t 0 sets the timeout to 0 seconds before shutting down
            # The shutdown command cannot be canceled when run with these parameters
            subprocess.run(["shutdown", "/s", "/f", "/t", "0"], check=True)
        except Exception as e:
            logger.error(f"Failed to execute shutdown: {str(e)}")
            
            # As a fallback if the shutdown command fails
            try:
                os.system("shutdown /s /f /t 0")
            except:
                logger.critical("All shutdown attempts failed")
            
    def get_device_info(self, device):
        info = {}
        
        try:
            # Basic device information
            info['manufacturer'] = device.Manufacturer if hasattr(device, 'Manufacturer') and device.Manufacturer else 'Unknown'
            info['product'] = device.Description if hasattr(device, 'Description') and device.Description else 'Unknown'
            info['device_path'] = device.DeviceID if hasattr(device, 'DeviceID') and device.DeviceID else 'Unknown'
            info['serial'] = 'Unknown'
            info['vendor_id'] = 'Unknown'
            info['product_id'] = 'Unknown'
            info['drive_letter'] = None  # We'll fill this later if it's a storage device
            
            # Extract VID/PID from device ID
            if hasattr(device, 'DeviceID') and device.DeviceID:
                device_id = device.DeviceID
                if 'VID_' in device_id and 'PID_' in device_id:
                    vid_start = device_id.find('VID_') + 4
                    pid_start = device_id.find('PID_') + 4
                    
                    if vid_start > 3 and pid_start > 3:
                        vid_end = min(vid_start + 4, len(device_id))
                        pid_end = min(pid_start + 4, len(device_id))
                        
                        info['vendor_id'] = f"0x{device_id[vid_start:vid_end]}"
                        info['product_id'] = f"0x{device_id[pid_start:pid_end]}"
            
            # Extract serial from PNP device ID
            if hasattr(device, 'PNPDeviceID') and device.PNPDeviceID:
                pnp_id = device.PNPDeviceID
                if '\\' in pnp_id:
                    parts = pnp_id.split('\\')
                    if len(parts) > 2:
                        info['serial'] = parts[2]
            
        except Exception as e:
            logger.debug(f"Error getting device info: {str(e)}")
            
        return info
    
    def get_drive_letter_for_device(self, device_id):
        """Get the drive letter for a USB storage device."""
        try:
            # Initialize COM for this thread
            pythoncom.CoInitialize()
            try:
                wmi_obj = wmi.WMI()
                # Query logical disks
                logical_disks = wmi_obj.query("SELECT * FROM Win32_LogicalDisk WHERE DriveType=2")  # Type 2 is removable disk
                
                for disk in logical_disks:
                    # Return the first removable drive found
                    return disk.DeviceID
                    
                return None
            finally:
                pythoncom.CoUninitialize()
        except Exception as e:
            logger.error(f"Error getting drive letter: {str(e)}")
            return None
    
    def format_device_message(self, device_info, action, timestamp):
        message = f"USB Event Details:\n"
        message += f"Action: {action}\n"
        message += f"Time: {timestamp}\n"
        message += f"Host: {self.hostname} ({self.ip_address})\n\n"
        message += f"Device Information:\n"
        message += f"  Manufacturer: {device_info.get('manufacturer', 'Unknown')}\n"
        message += f"  Product: {device_info.get('product', 'Unknown')}\n"
        message += f"  Serial: {device_info.get('serial', 'Unknown')}\n"
        message += f"  Vendor ID: {device_info.get('vendor_id', 'Unknown')}\n"
        message += f"  Product ID: {device_info.get('product_id', 'Unknown')}\n"
        message += f"  Device Path: {device_info.get('device_path', 'Unknown')}\n"
        
        if device_info.get('drive_letter'):
            message += f"  Drive Letter: {device_info.get('drive_letter')}\n"
        
        return message
    
    def get_usb_devices(self):
        devices = {}
        try:
            # Initialize COM for this thread
            pythoncom.CoInitialize()
            try:
                wmi_obj = wmi.WMI()
                # Query only removable USB devices
                usb_devices = wmi_obj.query("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%USB%' AND DeviceID LIKE '%VID_%'")
                
                # Also get logical disks to match drive letters
                logical_disks = wmi_obj.query("SELECT * FROM Win32_LogicalDisk WHERE DriveType=2")  # Type 2 is removable disk
                drive_letters = [disk.DeviceID for disk in logical_disks]
                
                for device in usb_devices:
                    # Skip USB hubs and internal devices
                    if hasattr(device, 'Description') and device.Description:
                        if "hub" in device.Description.lower():
                            continue
                        # Skip likely internal devices with these keywords
                        if any(keyword in device.Description.lower() for keyword in 
                               ["keyboard", "mouse", "camera", "webcam", "controller", "audio", "bluetooth", "monitor", "root hub", "composite"]):
                            continue

                    device_info = self.get_device_info(device)
                    
                    # Check if this is a storage device by checking if it has a driver letter
                    # Assign drive letter if available
                    device_info['drive_letter'] = drive_letters[0] if drive_letters else None
                    
                    device_id = f"{device_info.get('vendor_id')}_{device_info.get('product_id')}_{device_info.get('serial')}"
                    devices[device_id] = device_info
            finally:
                # Always uninitialize COM when done with WMI operations
                pythoncom.CoUninitialize()
                
        except Exception as e:
            logger.error(f"Error retrieving USB devices: {str(e)}")
            
        return devices
        
    def start_monitoring(self):
        if self.running:
            return
            
        # Clear existing devices dictionary when starting fresh
        global connected_devices, active_threats
        connected_devices = {}
        active_threats = {}
        
        # Start monitoring in a separate thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("USB threat monitoring started")
        print("USB threat monitoring started. Waiting for USB devices...")
        
    def stop_monitoring(self):
        self.running = False
        if self.monitor_thread:
            try:
                self.monitor_thread.join(timeout=2.0)
            except:
                pass
                
        logger.info("USB monitoring stopped")
        print("USB monitoring stopped")
    
    def monitor(self):
        try:
            # Initialize COM for the monitor thread
            pythoncom.CoInitialize()
            
            try:
                logger.info("USB device monitoring started")
                
                while self.running:
                    try:
                        # Check for device changes
                        self.check_devices()
                        
                        # Avoid high CPU usage
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in monitoring: {str(e)}")
                        time.sleep(5)
            finally:
                # Uninitialize COM when thread ends
                pythoncom.CoUninitialize()
                    
        except Exception as e:
            logger.error(f"Error in monitor loop: {str(e)}")
    
    def scan_device(self, device_id, device_info):
        """Scan a device for threats."""
        drive_letter = device_info.get('drive_letter')
        if not drive_letter:
            logger.debug(f"No drive letter for device {device_id}, skipping scan")
            return
            
        try:
            logger.info(f"Scanning {drive_letter} for threats...")
            print(f"Scanning USB drive {drive_letter} for threats...")
                
            # Scan the drive
            threats = self.threat_scanner.scan_usb_drive(drive_letter)
            
            if threats:
                logger.warning(f"Found {len(threats)} threats on {drive_letter}")
                print(f"ALERT: Found {len(threats)} potential threats on {drive_letter}")
                
                # Format threat details for logging
                threat_details = "\n".join([f"- {t['threat_info']} ({t['file_path']})" for t in threats])
                logger.warning(f"Threat details:\n{threat_details}")
                print(f"Threat details:\n{threat_details}")
                
                # Send email notification about threats
                subject = f"CRITICAL: USB Threats Detected on {self.hostname}"
                email_message = f"USB Threat Detection Alert:\n\n"
                email_message += f"Security threat detected on USB drive {drive_letter}!\n\n"
                email_message += f"Threat details:\n{threat_details}\n\n"
                email_message += f"The system will shut down in {SHUTDOWN_DELAY} seconds.\n\n"
                email_message += f"Host: {self.hostname} ({self.ip_address})"
                
                email_thread = threading.Thread(target=self.email_sender.send, args=(subject, email_message))
                email_thread.daemon = True
                email_thread.start()
                
                # Execute shutdown immediately
                self.execute_shutdown(device_id, drive_letter)
            else:
                logger.info(f"No threats found on {drive_letter}")
                print(f"No threats found on {drive_letter}")
                    
        except Exception as e:
            logger.error(f"Error scanning device {device_id}: {str(e)}")
            
    def check_devices(self):
        # Get current USB devices
        current_devices = self.get_usb_devices()
        
        with self.lock:
            # Check for new devices
            for device_id, device_info in current_devices.items():
                if device_id not in connected_devices:
                    logger.info(f"USB device connected: {device_id}")
                    connected_devices[device_id] = device_info
                    
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    subject = f"USB Device Connected: {device_info.get('manufacturer', 'Unknown')} {device_info.get('product', 'Unknown')}"
                    message = self.format_device_message(device_info, "Connected", timestamp)
                    
                    print(f"USB device connected: {device_info.get('manufacturer', 'Unknown')} {device_info.get('product', 'Unknown')} - {device_info.get('drive_letter', '')}")
                    
                    # Use threading for email sending to prevent freezing
                    email_thread = threading.Thread(target=self.email_sender.send, args=(subject, message))
                    email_thread.daemon = True
                    email_thread.start()
                    
                    # Scan the device for threats immediately
                    if device_info.get('drive_letter'):
                        self.scan_device(device_id, device_info)
            
            # Check for removed devices
            device_ids_to_remove = []
            for device_id, device_info in connected_devices.items():
                if device_id not in current_devices:
                    logger.info(f"USB device disconnected: {device_id}")
                    device_ids_to_remove.append(device_id)
                    
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    subject = f"USB Device Disconnected: {device_info.get('manufacturer', 'Unknown')} {device_info.get('product', 'Unknown')}"
                    message = self.format_device_message(device_info, "Disconnected", timestamp)
                    
                    print(f"USB device disconnected: {device_info.get('manufacturer', 'Unknown')} {device_info.get('product', 'Unknown')} - {device_info.get('drive_letter', '')}")
                    
                    # Use threading for email sending to prevent freezing
                    email_thread = threading.Thread(target=self.email_sender.send, args=(subject, message))
                    email_thread.daemon = True
                    email_thread.start()
            
            # Remove disconnected devices
            for device_id in device_ids_to_remove:
                del connected_devices[device_id]

def main():
    # Set up email settings
    email_config = {
       'from_email': 'your-email@example.com',
    'to_email': 'alerts-email@example.com',
    'smtp_server': 'smtp.example.com',
    'smtp_port': 587,
    'username': 'your-username',
    'password': 'your-password'
    }
    
    # Save email config
    try:
        with open("email_config.json", "w") as f:
            json.dump(email_config, f)
    except Exception as e:
        logger.error(f"Error saving email config: {str(e)}")
    
    try:
        print("=== USB Device Threat Monitor ===")
        print("Monitoring for USB devices and automatically scanning for threats.")
        print("WARNING: If threats are detected, system will shut down after 3 seconds with NO option to cancel.")
        print("Press Ctrl+C to stop monitoring (if no threats detected).\n")
        
        # Create and start the monitor
        monitor = DeviceMonitor(email_config)
        monitor.start_monitoring()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping USB monitoring...")
        if 'monitor' in locals():
            monitor.stop_monitoring()
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
