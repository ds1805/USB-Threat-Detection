# USB Threat Detection and Monitoring System

A comprehensive security tool that monitors USB devices for malicious content and provides automated responses to potential threats. This Windows-based utility runs silently in the background, scanning connected USB storage devices for suspicious files, malware signatures, and potentially harmful patterns.

## Core Features

- Real-time detection of USB device connections and disconnections
- Automated scanning of connected USB drives for security threats
- Email notifications for device events and security alerts
- Configurable threat response including automated system shutdown
- Runs as a Windows service or background process
- Startup integration for continuous protection

## Technical Implementation

The system uses file signature analysis, pattern matching, and known threat detection to identify potentially malicious files on USB drives. When threats are detected, the system can automatically shut down the computer to prevent further compromise while sending detailed notifications to security personnel.

## Dependencies

- **Python 3.6+**: Core programming language
- **wmi**: Windows Management Instrumentation interface for Python
- **pywin32**: Python extensions for Windows
- **python-magic-bin**: File type identification library
- **smtplib** (standard library): For email notifications
- **ctypes** (standard library): For Windows API access
- **win32service/win32serviceutil**: For Windows service implementation
- **hashlib** (standard library): For file hash calculation
- **re** (standard library): For pattern matching
- **threading** (standard library): For asynchronous operations

## Installation Requirements

- Windows operating system (7/8/10/11)
- Administrator privileges (required for service installation)
- Network connectivity (for email notifications)
- Python environment with required dependencies installed

This solution is ideal for corporate environments, sensitive systems, or any scenario where USB-based attacks pose a significant security risk.
