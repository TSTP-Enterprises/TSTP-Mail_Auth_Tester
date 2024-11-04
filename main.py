import sys
import smtplib
import logging
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QCheckBox, QComboBox, QMessageBox, QGridLayout,
    QDialog, QTextEdit, QFormLayout, QSizePolicy, QAction, QMenu, QMenuBar, 
    QInputDialog, QTabWidget, QScrollArea, QTextBrowser
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QPoint, QTimer
from PyQt5.QtGui import QIcon, QFont
import os
import requests

# ===========================
# Configuration
# ===========================
LOG_DIRECTORY = 'logs'  # Directory to save log files
os.makedirs(LOG_DIRECTORY, exist_ok=True)

# ===========================
# Resource Path
# ===========================   
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

# ===========================
# Logging Setup
# ===========================
def setup_logging():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(LOG_DIRECTORY, f"smtp_tester_{timestamp}.log")
    logger = logging.getLogger('SMTPTester')
    logger.setLevel(logging.DEBUG)
    # File Handler
    fh = logging.FileHandler(log_filename)
    fh.setLevel(logging.DEBUG)
    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # Add Handlers
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = setup_logging()

# ===========================
# Logging to GUI via Signal
# ===========================
class LogEmitter(QObject):
    log_signal = pyqtSignal(str)

class QtHandler(logging.Handler):
    def __init__(self, emitter):
        super().__init__()
        self.emitter = emitter
    
    def emit(self, record):
        log_entry = self.format(record)
        self.emitter.log_signal.emit(log_entry)

# Initialize LogEmitter and QtHandler
log_emitter = LogEmitter()
qt_handler = QtHandler(log_emitter)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
qt_handler.setFormatter(formatter)
logger.addHandler(qt_handler)

# ===========================
# Custom Message Box
# ===========================
class CustomMessageBox(QDialog):
    def __init__(self, message, title="Message", icon_type="info", solutions=None):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(550, 500)
        self.initUI(message, icon_type, solutions)
    
    def initUI(self, message, icon_type, solutions):
        layout = QVBoxLayout()
        # Icon and Message
        if icon_type == "info":
            icon = QLabel("ℹ️")
            icon.setStyleSheet("font-size: 48px; color: #3498db;")
        elif icon_type == "warning":
            icon = QLabel("⚠️")
            icon.setStyleSheet("font-size: 48px; color: #f1c40f;")
        elif icon_type == "error":
            icon = QLabel("❌")
            icon.setStyleSheet("font-size: 48px; color: #e74c3c;")
        else:
            icon = QLabel("ℹ️")
            icon.setStyleSheet("font-size: 48px; color: #3498db;")
        
        icon.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon)
        
        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setAlignment(Qt.AlignCenter)
        msg_label.setFont(QFont('Arial', 12))
        layout.addWidget(msg_label)
        
        if solutions:
            solutions_label = QLabel("Possible Solutions:")
            solutions_label.setFont(QFont('Arial', 12, QFont.Bold))
            layout.addWidget(solutions_label)
            for solution in solutions:
                sol_label = QLabel(f"- {solution}")
                sol_label.setWordWrap(True)
                sol_label.setFont(QFont('Arial', 10))
                layout.addWidget(sol_label)
        
        # OK Button
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        ok_button.setFixedWidth(100)
        ok_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        layout.addWidget(ok_button, alignment=Qt.AlignCenter)
        self.setLayout(layout)

# ===========================
# Console Log Window
# ===========================
class ConsoleLogWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Console Log")
        self.setFixedSize(800, 600)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont('Courier', 10))
        layout.addWidget(self.log_text)
        self.setLayout(layout)
    
    def append_log(self, message):
        self.log_text.append(message)

# ===========================
# TSTP Mail Auth Tester Worker
# ===========================
class SMTPTesterWorker(QThread):
    success_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str, list)  # Error message and possible solutions

    def __init__(self, smtp_settings, recipient=None):
        super().__init__()
        self.smtp_settings = smtp_settings
        self.recipient = recipient
        self.timer = QTimer()
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.handle_timeout)
    
    def run(self):
        self.timer.start(15000)  # 15 seconds timeout
        server = self.smtp_settings['server']
        port = self.smtp_settings['port']
        use_ssl = self.smtp_settings['use_ssl']
        use_auth = self.smtp_settings['use_auth']
        email = self.smtp_settings['email']
        username = self.smtp_settings['username']
        password = self.smtp_settings['password']
        encryption = self.smtp_settings['encryption']
        
        logger.info("Starting SMTP test with the following parameters:")
        logger.info(f"Server: {server}")
        logger.info(f"Port: {port}")
        logger.info(f"Use SSL: {use_ssl}")
        logger.info(f"Use SMTP Authentication: {use_auth}")
        logger.info(f"SMTP Authentication Email: {email}")
        logger.info(f"SMTP Authentication Username: {username}")
        logger.info(f"SMTP Authentication Encryption: {encryption}")

        # Basic Validation
        if not server or not port:
            logger.warning("Server and port must be provided.")
            self.error_signal.emit("Please enter both SMTP server and port number.", ["Ensure that the SMTP server address and port number are correctly entered."])
            return

        try:
            port = int(port)
            if not (0 < port < 65536):
                raise ValueError
        except ValueError:
            logger.warning("Invalid port number.")
            self.error_signal.emit("Port must be a valid number between 1 and 65535.", ["Enter a valid port number. Common ports are 465 (SSL) and 587 (TLS)."])
            return

        if use_auth:
            if not all([email, username, password]):
                logger.warning("Authentication fields are incomplete.")
                self.error_signal.emit("Please fill in all authentication fields.", ["Ensure that email, username, and password are correctly entered."])
                return

        # Prevent SSL on ports that expect STARTTLS
        if use_ssl and port == 587:
            logger.warning("SSL is not typically used with port 587.")
            self.error_signal.emit(
                "Mismatch detected: Port 587 typically requires STARTTLS (use TLS instead of SSL).",
                [
                    "Uncheck 'Use SSL' if you're using port 587.",
                    "Alternatively, use port 465 for SSL connections."
                ]
            )
            return

        try:
            logger.info("Attempting to establish SMTP connection...")
            if use_ssl:
                smtp = smtplib.SMTP_SSL(server, port, timeout=10)
                logger.info("Using SMTP_SSL for connection.")
            else:
                smtp = smtplib.SMTP(server, port, timeout=10)
                logger.info("Using SMTP for connection without SSL.")
                smtp.ehlo()
                if encryption in ['AUTO', 'ACTIVE']:
                    smtp.starttls()
                    logger.info("STARTTLS initiated.")
            
            if use_auth:
                logger.info("Attempting to log in with provided credentials...")
                smtp.login(username, password)
                logger.info("Authentication successful.")
            
            # Send a test email
            from_addr = email
            to_addr = self.recipient if self.recipient else email
            message = f"""\
From: {from_addr}
To: {to_addr}
Subject: SMTP Test Email from The Solutions To Problems (TSTP)
MIME-Version: 1.0
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }}
        .container {{
            width: 80%;
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 10px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }}
        .header h1 {{
            color: #1abc9c;
            margin: 0;
        }}
        .content {{
            margin-top: 20px;
        }}
        .content p {{
            margin: 10px 0;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.9em;
            color: #777;
            border-top: 1px solid #ddd;
            padding-top: 20px;
        }}
        .footer a {{
            color: #1abc9c;
            text-decoration: none;
        }}
        .button {{
            display: inline-block;
            padding: 10px 20px;
            margin: 20px 10px;
            font-size: 1em;
            color: #fff;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            text-align: center;
        }}
        .button-website {{
            background-color: #1abc9c;
        }}
        .button-website:hover {{
            background-color: #16a085;
        }}
        .button-github {{
            background-color: #6e6e6e;
        }}
        .button-github:hover {{
            background-color: #5a5a5a;
        }}
        .button-linkedin {{
            background-color: #0077b5;
        }}
        .button-linkedin:hover {{
            background-color: #005582;
        }}
        .button-youtube {{
            background-color: #ff0000;
        }}
        .button-youtube:hover {{
            background-color: #cc0000;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>The Solutions To Problems (TSTP)</h1>
        </div>
        <div class="content">
            <p>Dear User,</p>
            <p>You are receiving this email because a test was conducted to verify the SMTP settings for The Solutions To Problems (TSTP) software. This email confirms that the SMTP configuration is correct and operational.</p>
            <p>If you are the intended recipient and initiated this test, no further action is required. If you received this email in error, please disregard it.</p>
            <p>Our software, TSTP, is designed to help you with various productivity, testing, and other needs. We offer a range of programs that can enhance your workflow and efficiency.</p>
            <p>For more information about our services and to download our software, please visit our website at <a href="https://www.tstp.xyz">https://www.tstp.xyz</a>.</p>
            <p>You can also access our code on our GitHub repository at <a href="https://github.com/TSTP-Enterprises">https://github.com/TSTP-Enterprises</a>.</p>
            <div style="text-align: center;">
                <a href="https://www.tstp.xyz" class="button button-website">TSTP.xyz</a>
                <a href="https://github.com/TSTP-Enterprises" class="button button-github">TSTP GitHub</a>
                <a href="https://www.linkedin.com/company/thesolutions-toproblems" class="button button-linkedin">TSTP LinkedIn</a>
                <a href="https://www.youtube.com/@yourpststudios" class="button button-youtube">TSTP YouTube</a>
            </div>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Solutions To Problems (TSTP) Team</p>
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
            smtp.sendmail(from_addr, to_addr, message)
            smtp.quit()
            logger.info("Test email sent successfully.")
            self.success_signal.emit(
                f"✅ SMTP settings are correct.\nTest email sent successfully!\n"
                f"From: {from_addr}\n"
                f"To: {to_addr}\n"
                f"SMTP Server: {server}\n"
                f"Port: {port}\n"
                f"SSL Used: {'Yes' if use_ssl else 'No'}\n"
                f"SMTP Authentication: {'Yes' if use_auth else 'No'}"
            )
        
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTPAuthenticationError: {e}")
            self.error_signal.emit(
                f"❌ Authentication Error:\nFailed to authenticate with the provided credentials.\nDetails: {e}",
                [
                    "Verify that the email address and password are correct.",
                    "Ensure that the account is not locked or disabled.",
                    "If using Microsoft 365, consider using an app-specific password if MFA is enabled.",
                    "Contact your administrator to resolve account restrictions."
                ]
            )
        
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTPConnectError: {e}")
            self.error_signal.emit(
                f"❌ Connection Error:\nFailed to connect to the SMTP server.\nDetails: {e}",
                [
                    "Verify that the SMTP server address and port number are correct.",
                    "Ensure that your network allows outbound connections on the specified port.",
                    "Check if the SMTP server is operational and reachable."
                ]
            )
        
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTPRecipientsRefused: {e}")
            self.error_signal.emit(
                f"❌ Recipient Refused:\nThe server did not accept the recipient address.\nDetails: {e}",
                [
                    "Verify the recipient email address for correctness.",
                    "Ensure that the recipient's email server is operational and not blocking your emails."
                ]
            )
        
        except smtplib.SMTPException as e:
            logger.error(f"SMTPException: {e}")
            self.error_signal.emit(
                f"❌ SMTP Error:\nAn SMTP error occurred.\nDetails: {e}",
                [
                    "Check your SMTP server settings.",
                    "Ensure that your internet connection is stable.",
                    "Review the SMTP server documentation for specific error codes."
                ]
            )
        
        except Exception as e:
            logger.error(f"Unexpected Exception: {e}")
            self.error_signal.emit(
                f"❌ Unexpected Error:\nAn unexpected error occurred.\nDetails: {e}",
                [
                    "Ensure that all fields are correctly filled.",
                    "Check your internet connection.",
                    "Try restarting the application and retrying the operation."
                ]
            )
        finally:
            self.timer.stop()

    def handle_timeout(self):
        logger.error("Operation timed out after 15 seconds.")
        self.error_signal.emit(
            "❌ Timeout Error:\nThe operation timed out after 15 seconds.",
            [
                "Check your internet connection.",
                "Ensure that the SMTP server is operational and reachable.",
                "Try again later."
            ]
        )

# ===========================
# Main TSTP Mail Auth Tester UI
# ===========================
class SMTPTesterUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('TSTP Mail Auth Tester')
        self.setFixedSize(550, 400)  # Adjust as needed
        self.current_theme = 'light'
        self.console_log_window = ConsoleLogWindow()
        self.initUI()
        self.apply_theme(self.current_theme)
    
    def initUI(self):
        # Central Widget
        central_widget = QWidget()
        # Icon
        icon = QIcon(resource_path('app_icon.ico'))
        self.setWindowIcon(icon)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Custom Title Bar
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(40)
        self.title_bar.setStyleSheet("background-color: #2c3e50; color: white;")
        title_layout = QHBoxLayout()
        title_layout.setContentsMargins(10, 0, 10, 0)
        self.title_label = QLabel("TSTP Mail Auth Tester")
        self.title_label.setFont(QFont('Arial', 16, QFont.Bold))
        self.title_label.setAlignment(Qt.AlignCenter)
        title_layout.addWidget(self.title_label)
        
        # Menu Bar
        self.menu_bar = QMenuBar()
        self.setMenuBar(self.menu_bar)
        
        # View Menu
        view_menu = self.menu_bar.addMenu("View")
        toggle_theme_action = QAction("Toggle Dark/Light Theme", self)
        toggle_theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(toggle_theme_action)
        show_log_action = QAction("Show Console Log", self)
        show_log_action.triggered.connect(self.show_console_log)
        view_menu.addAction(show_log_action)
        
        # Help Menu
        help_menu = self.menu_bar.addMenu("Help")
        donate_action = QAction("Donate", self)
        donate_action.triggered.connect(lambda: self.open_link("https://www.paypal.com/donate/?hosted_button_id=RAAYNUTMHPQQN"))
        help_menu.addAction(donate_action)
        tutorial_action = QAction("Tutorial", self)
        tutorial_action.triggered.connect(self.open_tutorial)
        help_menu.addAction(tutorial_action)
        
        # About Menu
        about_menu = self.menu_bar.addMenu("About")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        about_menu.addAction(about_action)
        
        # Feedback Menu
        feedback_menu = self.menu_bar.addMenu("Feedback")
        feedback_action = QAction("Submit Feedback", self)
        feedback_action.triggered.connect(self.show_feedback)
        feedback_menu.addAction(feedback_action)
        
        # Form Layout for Inputs
        form_layout = QGridLayout()
        form_layout.setSpacing(10)
        
        label_size = (200, 30)
        input_size = (300, 30)
        
        # Email Provider Dropdown
        provider_label = QLabel('Email Provider:')
        provider_label.setFixedSize(*label_size)
        self.provider_dropdown = QComboBox()
        self.provider_dropdown.addItems(['Microsoft', 'Google', 'Yahoo', 'Custom'])
        self.provider_dropdown.setFixedSize(*input_size)
        self.provider_dropdown.currentIndexChanged.connect(self.update_server_address)
        form_layout.addWidget(provider_label, 0, 0)
        form_layout.addWidget(self.provider_dropdown, 0, 1)
        
        # SMTP Server Name
        server_label = QLabel('SMTP Server Name:')
        server_label.setFixedSize(*label_size)
        self.server_input = QLineEdit('smtp.office365.com')
        self.server_input.setFixedSize(*input_size)
        self.server_input.setEnabled(False)  # Initially disabled
        form_layout.addWidget(server_label, 1, 0)
        form_layout.addWidget(self.server_input, 1, 1)
        
        # Method to update server address based on dropdown selection
        def update_server_address(self):
            provider = self.provider_dropdown.currentText()
            if provider == 'Microsoft':
                self.server_input.setText('smtp.office365.com')
                self.server_input.setEnabled(False)
            elif provider == 'Google':
                self.server_input.setText('smtp.gmail.com')
                self.server_input.setEnabled(False)
            elif provider == 'Yahoo':
                self.server_input.setText('smtp.mail.yahoo.com')
                self.server_input.setEnabled(False)
            else:  # Custom
                self.server_input.setText('')
                self.server_input.setEnabled(True)
        
        # SMTP Port Number
        port_label = QLabel('SMTP Port Number:')
        port_label.setFixedSize(*label_size)
        self.port_input = QLineEdit('587')
        self.port_input.setFixedSize(*input_size)
        form_layout.addWidget(port_label, 2, 0)
        form_layout.addWidget(self.port_input, 2, 1)
        
        # Use SSL
        self.ssl_checkbox = QCheckBox('Use SSL')
        self.ssl_checkbox.setChecked(False)  # Unchecked by default for port 587
        self.ssl_checkbox.stateChanged.connect(self.toggle_ssl_port)
        form_layout.addWidget(self.ssl_checkbox, 3, 0, 1, 2)
        
        # Use SMTP Authentication
        self.auth_checkbox = QCheckBox('Use SMTP Authentication')
        self.auth_checkbox.setChecked(True)
        self.auth_checkbox.stateChanged.connect(self.toggle_auth_fields)
        form_layout.addWidget(self.auth_checkbox, 4, 0, 1, 2)
        
        # SMTP Authentication Email Address
        auth_email_label = QLabel('SMTP Authentication Email:')
        auth_email_label.setFixedSize(*label_size)
        self.auth_email_input = QLineEdit()
        self.auth_email_input.setFixedSize(*input_size)
        self.auth_email_input.setEnabled(True)
        form_layout.addWidget(auth_email_label, 5, 0)
        form_layout.addWidget(self.auth_email_input, 5, 1)
        
        # SMTP Authentication Username
        auth_username_label = QLabel('SMTP Authentication Username:')
        auth_username_label.setFixedSize(*label_size)
        self.auth_username_input = QLineEdit()
        self.auth_username_input.setFixedSize(*input_size)
        self.auth_username_input.setEnabled(True)
        form_layout.addWidget(auth_username_label, 6, 0)
        form_layout.addWidget(self.auth_username_input, 6, 1)
        
        # SMTP Authentication Password
        auth_password_label = QLabel('SMTP Authentication Password:')
        auth_password_label.setFixedSize(*label_size)
        self.auth_password_input = QLineEdit()
        self.auth_password_input.setFixedSize(*input_size)
        self.auth_password_input.setEchoMode(QLineEdit.Password)
        self.auth_password_input.setEnabled(True)
        form_layout.addWidget(auth_password_label, 7, 0)
        form_layout.addWidget(self.auth_password_input, 7, 1)
        
        # SMTP Authentication Encryption
        encryption_label = QLabel('SMTP Authentication Encryption:')
        encryption_label.setFixedSize(*label_size)
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(['AUTO', 'ACTIVE', 'INACTIVE'])
        self.encryption_combo.setFixedSize(*input_size)
        self.encryption_combo.setEnabled(True)
        form_layout.addWidget(encryption_label, 8, 0)
        form_layout.addWidget(self.encryption_combo, 8, 1)
        
        main_layout.addLayout(form_layout)
        
        # Test Button
        self.test_button = QPushButton('Test SMTP Settings')
        self.test_button.setFixedHeight(40)
        self.test_button.setFont(QFont('Arial', 12))
        self.test_button.clicked.connect(self.test_smtp)
        self.test_button.setStyleSheet("""
            QPushButton {
                background-color: #1abc9c;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #16a085;
            }
        """)
        main_layout.addWidget(self.test_button)

    def update_server_address(self):
        provider = self.provider_dropdown.currentText()
        if provider == 'Microsoft':
            self.server_input.setText('smtp.office365.com')
            self.server_input.setEnabled(False)
        elif provider == 'Google':
            self.server_input.setText('smtp.gmail.com')
            self.server_input.setEnabled(False)
        elif provider == 'Yahoo':
            self.server_input.setText('smtp.mail.yahoo.com')
            self.server_input.setEnabled(False)
        else:  # Custom
            self.server_input.setText('')
            self.server_input.setEnabled(True)

    def toggle_ssl_port(self, state):
        if state == Qt.Checked:
            self.port_input.setText('465')
        else:
            self.port_input.setText('587')
    
    def toggle_auth_fields(self, state):
        enabled = state == Qt.Checked
        self.auth_email_input.setEnabled(enabled)
        self.auth_username_input.setEnabled(enabled)
        self.auth_password_input.setEnabled(enabled)
        self.encryption_combo.setEnabled(enabled)
        logger.info(f"SMTP Authentication toggled to {'enabled' if enabled else 'disabled'}.")
    
    def test_smtp(self):
        server = self.server_input.text().strip()
        port = self.port_input.text().strip()
        use_ssl = self.ssl_checkbox.isChecked()
        use_auth = self.auth_checkbox.isChecked()
        email = self.auth_email_input.text().strip()
        username = self.auth_username_input.text().strip()
        password = self.auth_password_input.text().strip()
        encryption = self.encryption_combo.currentText()
        
        smtp_settings = {
            'server': server,
            'port': port,
            'use_ssl': use_ssl,
            'use_auth': use_auth,
            'email': email,
            'username': username,
            'password': password,
            'encryption': encryption
        }
        
        # Disable test button to prevent multiple clicks
        self.test_button.setEnabled(False)
        self.test_button.setText("Testing...")
        
        # Ask if they want to send the email to a specific address
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Send Test Email")
        msg_box.setText("Do you want to send the test email to a specific address?")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        
        if msg_box.exec_() == QMessageBox.Yes:
            address, ok = QInputDialog.getText(self, "Recipient Address", "Enter the recipient email address:")
            if ok and address:
                recipient = address
            else:
                recipient = 'test@tstp.xyz'
        else:
            recipient = 'test@tstp.xyz'
        
        # Start the SMTP test in a separate thread
        self.worker = SMTPTesterWorker(smtp_settings, recipient)
        self.worker.success_signal.connect(self.handle_success)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def handle_success(self, message):
        self.test_button.setEnabled(True)
        self.test_button.setText("Test SMTP Settings")
        msg_box = CustomMessageBox(message, "Success", "info")
        msg_box.exec_()
        logger.info("SMTP test completed successfully.")
    
    def handle_error(self, error_message, solutions):
        self.test_button.setEnabled(True)
        self.test_button.setText("Test SMTP Settings")
        msg_box = CustomMessageBox(error_message, "Error", "error", solutions)
        msg_box.exec_()
        logger.error(f"SMTP test failed: {error_message}")
    
    def toggle_theme(self):
        if self.current_theme == 'dark':
            self.apply_theme('light')
        else:
            self.apply_theme('dark')
    
    def apply_theme(self, theme):
        if theme == 'dark':
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #121212;
                    color: #e0e0e0;
                }
                QLabel {
                    color: #e0e0e0;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                    border: 1px solid #333333;
                    padding: 5px;
                    border-radius: 5px;
                }
                QPushButton {
                    background-color: #1abc9c;
                    color: white;
                    border: none;
                    padding: 10px;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #16a085;
                }
                QCheckBox {
                    color: #e0e0e0;
                }
                QMenuBar {
                    background-color: #121212;
                    color: white;
                }
                QMenuBar::item:selected {
                    background-color: #34495e;
                }
                QMenu {
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                }
                QMenu::item:selected {
                    background-color: #34495e;
                }
            """)
            self.current_theme = 'dark'
            logger.info("Theme changed to Dark.")
        else:
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #ffffff;
                    color: #000000;
                }
                QLabel {
                    color: #000000;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background-color: #f0f0f0;
                    color: #000000;
                    border: 1px solid #cccccc;
                    padding: 5px;
                    border-radius: 5px;
                }
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 10px;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                QMenuBar {
                    background-color: #f0f0f0;
                    color: #000000;
                }
                QMenuBar::item:selected {
                    background-color: #dcdcdc;
                }
                QMenu {
                    background-color: #ffffff;
                    color: #000000;
                }
                QMenu::item:selected {
                    background-color: #dcdcdc;
                }
            """)
            self.current_theme = 'light'
            logger.info("Theme changed to Light.")
    
    def show_console_log(self):
        if self.console_log_window.isVisible():
            self.console_log_window.hide()
        else:
            self.console_log_window.show()
    
    def open_link(self, url):
        import webbrowser
        webbrowser.open(url)

    def open_tutorial(self):
        tutorial_dialog = QDialog(self)
        tutorial_dialog.setWindowTitle("TSTP Mail Auth Tester Tutorial")
        tutorial_dialog.setFixedSize(900, 900)  # Further increased window size
        tutorial_dialog.setModal(True)

        # Apply theme styles
        if self.current_theme == 'dark':
            dialog_style = """
                QDialog {
                    background-color: #121212;
                    color: #e0e0e0;
                }
                QLabel {
                    color: #e0e0e0;
                }
                QTextEdit, QTextBrowser {
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                    border: 1px solid #333333;
                }
            """
        else:
            dialog_style = """
                QDialog {
                    background-color: #ffffff;
                    color: #000000;
                }
                QLabel {
                    color: #000000;
                }
                QTextEdit, QTextBrowser {
                    background-color: #f0f0f0;
                    color: #000000;
                    border: 1px solid #cccccc;
                }
            """
        tutorial_dialog.setStyleSheet(dialog_style)

        main_layout = QVBoxLayout()
        tutorial_dialog.setLayout(main_layout)

        # Tutorial Content
        tutorial_content = QTextBrowser()
        tutorial_content.setReadOnly(True)
        # Set height
        tutorial_content.setFixedHeight(300)
        tutorial_content.setHtml("""
        <h2 style="color: #3498db;">TSTP Mail Auth Tester Tutorial</h2>
        <p>Welcome to the TSTP Mail Auth Tester Tutorial. Follow the steps below to configure and test your SMTP settings:</p>
        <ol>
            <li>Enter the SMTP server name (e.g., smtp.office365.com).</li>
            <li>Enter the SMTP port number (e.g., 587 for TLS or 465 for SSL).</li>
            <li>Check the 'Use SSL' checkbox if you are using SSL.</li>
            <li>Check the 'Use SMTP Authentication' checkbox if your server requires authentication.</li>
            <li>Enter the SMTP authentication email address, username, and password.</li>
            <li>Click the 'Test SMTP Settings' button to send a test email and verify your settings.</li>
        </ol>
        <p>If you encounter any issues, refer to the 'Common Issues' section below.</p>
        """)
        tutorial_content.setFont(QFont('Arial', 12))
        tutorial_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        main_layout.addWidget(tutorial_content)

        # Tabs for Common Issues
        tabs = QTabWidget()
        tabs.setStyleSheet(self.get_tab_style())
        tabs.setTabsClosable(False)
        tabs.setMovable(False)

        # Function to create each SMTP settings tab
        def create_smtp_tab(provider_name, settings_html, additional_sections=None):
            tab = QWidget()
            tab_layout = QVBoxLayout()
            tab_layout.setContentsMargins(10, 10, 10, 10)
            # Set height
            tab.setFixedHeight(500)
            tab.setLayout(tab_layout)

            # Scroll Area for the tab content
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("background: transparent;")  # Make scroll area transparent
            scroll_content = QWidget()
            scroll_layout = QVBoxLayout()
            scroll_layout.setContentsMargins(0, 0, 0, 0)
            scroll_layout.setSpacing(10)
            scroll_content.setLayout(scroll_layout)

            # Provider Settings Description
            description_label = QTextBrowser()
            description_label.setReadOnly(True)
            description_label.setHtml(settings_html['description'])
            description_label.setFont(QFont('Arial', 11))
            description_label.setStyleSheet("border: none;")
            description_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            scroll_layout.addWidget(description_label)

            # Collapsible Sections
            collapsible_sections = settings_html.get('sections', [])
            for section in collapsible_sections:
                # Conditional display based on applicability
                if section.get('applicable', True):
                    box = CollapsibleBox(title=section['title'], theme=self.current_theme)
                    content_label = QTextBrowser()
                    content_label.setReadOnly(True)
                    content_label.setHtml(section['content'])
                    content_label.setFont(QFont('Arial', 10))
                    content_label.setStyleSheet("border: none;")
                    box.content_layout.addWidget(content_label)
                    scroll_layout.addWidget(box)

            # Add any additional sections if provided
            if additional_sections:
                for section in additional_sections:
                    if section.get('applicable', True):
                        box = CollapsibleBox(title=section['title'], theme=self.current_theme)
                        content_label = QTextBrowser()
                        content_label.setReadOnly(True)
                        content_label.setHtml(section['content'])
                        content_label.setFont(QFont('Arial', 10))
                        content_label.setStyleSheet("border: none;")
                        box.content_layout.addWidget(content_label)
                        scroll_layout.addWidget(box)

            # Spacer to push content to top
            scroll_layout.addStretch()
            scroll.setWidget(scroll_content)
            tab_layout.addWidget(scroll)

            return tab

        # Define settings for each provider
        smtp_settings = {
            "Google": {
                "description": """
                <h3 style='color: #db4437;'>Google SMTP Settings</h3>
                <p>For Google SMTP, use the following settings:</p>
                <ul>
                    <li><b>SMTP Server:</b> smtp.gmail.com</li>
                    <li><b>Port:</b> 587 (TLS) or 465 (SSL)</li>
                    <li><b>Use SSL:</b> Yes (for port 465)</li>
                    <li><b>Use SMTP Authentication:</b> Yes</li>
                    <li><b>Username:</b> Your full Gmail address (e.g., yourname@gmail.com)</li>
                    <li><b>Password:</b> Your Gmail password or App-specific password if 2FA is enabled</li>
                </ul>
                """,
                "sections": [
                    {
                        "title": "Authenticated SMTP",
                        "content": """
                        To enable authenticated SMTP for your Google account, follow these steps:
                        <ol>
                            <li>Go to your Google Account settings.</li>
                            <li>Navigate to the 'Security' section.</li>
                            <li>Enable 'Less secure app access' or generate an App-specific password if 2FA is enabled.</li>
                        </ol>
                        """
                    },
                    {
                        "title": "Security Defaults",
                        "content": """
                        Google enforces certain security defaults to protect your account. Ensure that you have enabled 'Less secure app access' or use an App-specific password if 2FA is enabled.
                        """
                    },
                    {
                        "title": "Client Support",
                        "content": """
                        Note that some email clients, such as Outlook, do not support authenticated SMTP. Consider using a different client or method for sending emails.
                        """
                    }
                ]
            },
            "Microsoft": {
                "description": """
                <h3 style='color: #0078d4;'>Microsoft SMTP Settings</h3>
                <p>For Microsoft SMTP, use the following settings:</p>
                <ul>
                    <li><b>SMTP Server:</b> smtp.office365.com</li>
                    <li><b>Port:</b> 587 (TLS) or 465 (SSL)</li>
                    <li><b>Use SSL:</b> Yes (for port 465)</li>
                    <li><b>Use SMTP Authentication:</b> Yes</li>
                    <li><b>Username:</b> Your full Office 365 email address (e.g., yourname@yourdomain.com)</li>
                    <li><b>Password:</b> Your Office 365 password or App-specific password if MFA is enabled</li>
                </ul>
                """,
                "sections": [
                    {
                        "title": "Authenticated SMTP",
                        "content": """
                        To enable authenticated SMTP for your Office 365 account, follow these steps:
                        <ol>
                            <li>Go to the Microsoft 365 admin center.</li>
                            <li>Navigate to 'Settings' > 'Org settings'.</li>
                            <li>Under 'Services', select 'Modern authentication'.</li>
                            <li>Ensure that 'Authenticated SMTP' is enabled.</li>
                        </ol>
                        """
                    },
                    {
                        "title": "Security Defaults",
                        "content": """
                        Microsoft enforces certain security defaults to protect your account. Ensure that you have enabled 'Authenticated SMTP' and consider using an App-specific password if MFA is enabled.
                        """
                    },
                    {
                        "title": "License Requirements",
                        "content": """
                        Ensure that your Office 365 account has the appropriate license assigned to use SMTP. Typically, an Exchange Online license is required.
                        """
                    },
                    {
                        "title": "Client Support",
                        "content": """
                        Note that some email clients, such as Outlook, do not support authenticated SMTP. Consider using a different client or method for sending emails.
                        """
                    }
                ]
            },
            "Yahoo": {
                "description": """
                <h3 style='color: #720e9e;'>Yahoo SMTP Settings</h3>
                <p>For Yahoo SMTP, use the following settings:</p>
                <ul>
                    <li><b>SMTP Server:</b> smtp.mail.yahoo.com</li>
                    <li><b>Port:</b> 587 (TLS) or 465 (SSL)</li>
                    <li><b>Use SSL:</b> Yes (for port 465)</li>
                    <li><b>Use SMTP Authentication:</b> Yes</li>
                    <li><b>Username:</b> Your full Yahoo email address (e.g., yourname@yahoo.com)</li>
                    <li><b>Password:</b> Your Yahoo password or App-specific password if 2FA is enabled</li>
                </ul>
                """,
                "sections": [
                    {
                        "title": "Authenticated SMTP",
                        "content": """
                        To enable authenticated SMTP for your Yahoo account, follow these steps:
                        <ol>
                            <li>Go to your Yahoo Account settings.</li>
                            <li>Navigate to the 'Account Security' section.</li>
                            <li>Enable 'Allow apps that use less secure sign in' or generate an App-specific password if 2FA is enabled.</li>
                        </ol>
                        """
                    },
                    {
                        "title": "Security Defaults",
                        "content": """
                        Yahoo enforces certain security defaults to protect your account. Ensure that you have enabled 'Allow apps that use less secure sign in' or use an App-specific password if 2FA is enabled.
                        """
                    },
                    {
                        "title": "Client Support",
                        "content": """
                        Note that some email clients, such as Outlook, do not support authenticated SMTP. Consider using a different client or method for sending emails.
                        """
                    }
                ]
            },
            "Custom": {
                "description": """
                <h3 style='color: #2c3e50;'>Custom SMTP Settings</h3>
                <p>For custom SMTP settings, use the following guidelines:</p>
                <ul>
                    <li><b>SMTP Server:</b> Your SMTP server address</li>
                    <li><b>Port:</b> The port number used by your SMTP server (e.g., 587 for TLS or 465 for SSL)</li>
                    <li><b>Use SSL:</b> Yes (for port 465)</li>
                    <li><b>Use SMTP Authentication:</b> Yes</li>
                    <li><b>Username:</b> Your SMTP authentication username</li>
                    <li><b>Password:</b> Your SMTP authentication password</li>
                </ul>
                """,
                "sections": [
                    {
                        "title": "Authenticated SMTP",
                        "content": """
                        To enable authenticated SMTP for your custom server, ensure that your server supports and is configured for authenticated SMTP. Refer to your server's documentation for specific instructions.
                        """
                    },
                    {
                        "title": "Security Defaults",
                        "content": """
                        Ensure that your custom server's security settings allow for authenticated SMTP and that any necessary security configurations are in place.
                        """,
                        "applicable": False  # Not applicable for Custom SMTP Settings
                    },
                    {
                        "title": "Client Support",
                        "content": """
                        Note that some email clients may not support authenticated SMTP. Ensure that your chosen client is compatible with your server's SMTP settings.
                        """
                    }
                ]
            }
        }

        # Create and add each tab
        for provider, settings in smtp_settings.items():
            tab = create_smtp_tab(provider, settings)
            tabs.addTab(tab, provider)

        # Apply custom styling to tabs
        tabs.setStyleSheet(self.get_tab_style())

        # Add tabs to layout
        main_layout.addWidget(tabs)

        # Spacer to push content to top
        main_layout.addStretch()

        # Close Button to close the dialog
        close_button = QPushButton("Close")
        close_button.setFixedWidth(150)
        close_button.setFont(QFont('Arial', 12))
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        close_button.clicked.connect(tutorial_dialog.accept)
        main_layout.addWidget(close_button, alignment=Qt.AlignCenter)

        tutorial_dialog.exec_()

    def get_tab_style(self):
        if self.current_theme == 'dark':
            return """
                QTabWidget::pane { /* The tab widget frame */
                    border-top: 2px solid #C2C7CB;
                }
                QTabBar::tab {
                    background: #2c3e50;
                    color: #ecf0f1;
                    padding: 10px;
                    border: 1px solid #34495e;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected, QTabBar::tab:hover {
                    background: #34495e;
                }
                QScrollBar:vertical {
                    background: #2c3e50;
                    width: 12px;
                    margin: 0px 0px 0px 0px;
                }
                QScrollBar::handle:vertical {
                    background: #34495e;
                    min-height: 20px;
                    border-radius: 6px;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    background: none;
                    height: 0px;
                }
            """
        else:
            return """
                QTabWidget::pane { /* The tab widget frame */
                    border-top: 2px solid #C2C7CB;
                }
                QTabBar::tab {
                    background: #f0f0f0;
                    color: #000000;
                    padding: 10px;
                    border: 1px solid #cccccc;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected, QTabBar::tab:hover {
                    background: #dcdcdc;
                }
                QScrollBar:vertical {
                    background: #f0f0f0;
                    width: 12px;
                    margin: 0px 0px 0px 0px;
                }
                QScrollBar::handle:vertical {
                    background: #cccccc;
                    min-height: 20px;
                    border-radius: 6px;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    background: none;
                    height: 0px;
                }
            """
        
    def show_about(self):
        about_dialog = QDialog(self)
        about_dialog.setWindowTitle("About TSTP Mail Auth Tester")
        about_dialog.setFixedSize(600, 400)
        
        layout = QVBoxLayout()
        
        about_content = QTextEdit()
        about_content.setReadOnly(True)
        about_content.setHtml("""
        <h3 style="color: #2c3e50;">About TSTP Mail Auth Tester</h3>
        <p>TSTP Mail Auth Tester is a comprehensive tool designed to help you test and troubleshoot SMTP authentication settings for various email providers. Whether you're configuring a new email account or diagnosing issues with an existing one, our tool provides the insights and functionality you need to ensure smooth email communication.</p>
        
        <h3 style="color: #2c3e50;">Features</h3>
        <ul>
            <li>Test SMTP server connectivity and authentication</li>
            <li>Support for multiple email providers including Google and Microsoft</li>
            <li>Detailed error messages and troubleshooting tips</li>
            <li>Console log for real-time monitoring</li>
            <li>Customizable settings for SSL/TLS and authentication methods</li>
        </ul>
        
        <h3 style="color: #2c3e50;">About The Solutions to Problems, LLC</h3>
        <p>The Solutions to Problems, LLC (TSTP) is dedicated to leveraging technology to solve real-world problems. Our mission is to create innovative solutions that empower individuals and organizations to achieve their goals. From custom software development to educational initiatives, we are committed to making a positive impact through technology.</p>
        
        <p>Visit our <a href="https://www.tstp.xyz" style="color: #3498db;">website</a> for more information about our projects and services.</p>
        """)
        layout.addWidget(about_content)
        
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(about_dialog.accept)
        ok_button.setFixedWidth(100)
        ok_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        layout.addWidget(ok_button, alignment=Qt.AlignCenter)
        
        about_dialog.setLayout(layout)
        about_dialog.exec_()
    
    def show_feedback(self):
        self.feedback_dialog = QDialog(self)
        self.feedback_dialog.setWindowTitle("Submit Feedback")
        self.feedback_dialog.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        
        feedback_label = QLabel("Please provide your feedback below:")
        layout.addWidget(feedback_label)
        
        self.feedback_text = QTextEdit()
        layout.addWidget(self.feedback_text)
        
        email_label = QLabel("Your Email (optional):")
        layout.addWidget(email_label)
        
        self.user_email = QLineEdit()
        layout.addWidget(self.user_email)
        
        submit_button = QPushButton("Submit")
        submit_button.clicked.connect(self.submit_feedback)
        submit_button.setFixedWidth(100)
        submit_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        layout.addWidget(submit_button, alignment=Qt.AlignCenter)
        
        self.feedback_dialog.setLayout(layout)
        self.feedback_dialog.exec_()
    
    def submit_feedback(self):
        feedback_text = self.feedback_text.toPlainText()
        user_email = self.user_email.text()
        program_name = "TSTP Mail Auth Tester"
        
        if not feedback_text:
            QMessageBox.warning(self, "Error", "Feedback cannot be empty")
            return
        
        try:
            response = requests.post(
                "https://tstp.xyz/mcadmin/public/combined_api_no_auth.php",
                data={"action": "submit_feedback", "feedback_text": feedback_text, "user_email": user_email, "program_name": program_name}
            )
            response_data = response.json()
            if response_data['status'] == 'success':
                QMessageBox.information(self, "Success", "Feedback submitted successfully")
            else:
                QMessageBox.warning(self, "Error", response_data['message'])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to submit feedback: {e}")
        finally:
            self.feedback_dialog.accept()
    
    def open_link(self, url):
        import webbrowser
        webbrowser.open(url)

# ===========================
# Custom Collapsible Box
# ===========================
class CollapsibleBox(QWidget):
    def __init__(self, title="", parent=None, theme='light'):
        super(CollapsibleBox, self).__init__(parent)

        self.theme = theme

        self.toggle_button = QPushButton(text=title)
        self.toggle_button.setStyleSheet(self.get_toggle_button_style())
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.clicked.connect(self.on_toggle)

        self.content_area = QWidget()
        self.content_area.setVisible(False)

        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(15, 0, 0, 0)
        self.content_area.setLayout(self.content_layout)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(0)
        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)

        self.setLayout(main_layout)

    def get_toggle_button_style(self):
        if self.theme == 'dark':
            return """
                QPushButton {
                    text-align: left;
                    font-weight: bold;
                    background-color: #2c3e50;
                    color: #ecf0f1;
                    border: none;
                    padding: 10px;
                }
                QPushButton::hover {
                    background-color: #34495e;
                }
                QPushButton::checked {
                    background-color: #34495e;
                }
            """
        else:
            return """
                QPushButton {
                    text-align: left;
                    font-weight: bold;
                    background-color: #f0f0f0;
                    color: #000000;
                    border: none;
                    padding: 10px;
                }
                QPushButton::hover {
                    background-color: #dcdcdc;
                }
                QPushButton::checked {
                    background-color: #dcdcdc;
                }
            """

    def on_toggle(self):
        checked = self.toggle_button.isChecked()
        self.content_area.setVisible(checked) 

# ===========================
# Main Execution
# ===========================
def main():
    app = QApplication(sys.argv)
    window = SMTPTesterUI()
    window.show()
    
    # Connect log emitter to console log window
    window.console_log_window = ConsoleLogWindow()
    log_emitter.log_signal.connect(window.console_log_window.append_log)
    #window.console_log_window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
