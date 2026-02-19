#!/usr/bin/env python3

import sys
import json
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QProgressBar, QSpinBox, QCheckBox, QComboBox,
    QMessageBox, QFileDialog, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon
from scanner import VulnerabilityScanner
from payload_manager import PayloadManager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScannerThread(QThread):
    """Background thread for scanning"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, url: str, depth: int, workers: int):
        super().__init__()
        self.url = url
        self.depth = depth
        self.workers = workers
    
    def run(self):
        try:
            self.progress.emit("Initializing scanner...")
            scanner = VulnerabilityScanner(max_workers=self.workers)
            
            self.progress.emit(f"Scanning {self.url}...")
            vulnerabilities = scanner.scan_url(self.url, self.depth)
            
            self.progress.emit("Scan complete!")
            self.finished.emit(vulnerabilities)
        except Exception as e:
            self.error.emit(str(e))

class APECPentestingTool(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("APEC Penetration Testing Tool")
        self.setGeometry(100, 100, 1400, 900)
        self.payload_manager = PayloadManager()
        self.current_vulnerabilities = []
        self.scanner_thread = None
        
        self.init_ui()
        self.apply_styles()
    
    def init_ui(self):
        """Initialize user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Tabs
        tabs = QTabWidget()
        tabs.addTab(self.create_scan_tab(), "🔍 Scanner")
        tabs.addTab(self.create_payloads_tab(), "💣 Payloads")
        tabs.addTab(self.create_results_tab(), "📊 Results")
        tabs.addTab(self.create_about_tab(), "ℹ️ About")
        
        main_layout.addWidget(tabs)
        central_widget.setLayout(main_layout)
    
    def create_header(self) -> QFrame:
        """Create application header"""
        header = QFrame()
        header.setStyleSheet("background-color: #1a1a2e; border-bottom: 2px solid #00d4ff;")
        layout = QVBoxLayout()
        
        title = QLabel("🛡️ APEC Penetration Testing Tool")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setStyleSheet("color: #00d4ff;")
        
        subtitle = QLabel("Professional Security Scanning with PayloadsAllTheThings Integration")
        subtitle.setStyleSheet("color: #a0a8c0;")
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        header.setLayout(layout)
        return header
    
    def create_scan_tab(self) -> QWidget:
        """Create scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # URL Input
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Scan Options
        options_layout = QHBoxLayout()
        
        options_layout.addWidget(QLabel("Scan Depth:"))
        self.depth_spinbox = QSpinBox()
        self.depth_spinbox.setMinimum(1)
        self.depth_spinbox.setMaximum(5)
        self.depth_spinbox.setValue(2)
        options_layout.addWidget(self.depth_spinbox)
        
        options_layout.addWidget(QLabel("Workers:"))
        self.workers_spinbox = QSpinBox()
        self.workers_spinbox.setMinimum(1)
        self.workers_spinbox.setMaximum(16)
        self.workers_spinbox.setValue(4)
        options_layout.addWidget(self.workers_spinbox)
        
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        # Scan Button
        self.scan_button = QPushButton("🚀 Start Scan")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #00d4ff;
                color: #0a0e27;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #00a8cc;
            }
            QPushButton:pressed {
                background-color: #0088aa;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #a0a8c0;")
        layout.addWidget(self.status_label)
        
        # Results Preview
        layout.addWidget(QLabel("Scan Results:"))
        self.scan_results_text = QTextEdit()
        self.scan_results_text.setReadOnly(True)
        self.scan_results_text.setMaximumHeight(300)
        layout.addWidget(self.scan_results_text)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_payloads_tab(self) -> QWidget:
        """Create payloads tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Vulnerability Type Selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Vulnerability Type:"))
        self.vuln_type_combo = QComboBox()
        self.vuln_type_combo.addItems([
            'xss', 'sql_injection', 'csrf', 'command_injection',
            'path_traversal', 'xxe', 'ldap', 'open_redirect'
        ])
        self.vuln_type_combo.currentTextChanged.connect(self.load_payloads)
        type_layout.addWidget(self.vuln_type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)
        
        # Payloads Display
        layout.addWidget(QLabel("Available Payloads:"))
        self.payloads_text = QTextEdit()
        self.payloads_text.setReadOnly(True)
        layout.addWidget(self.payloads_text)
        
        # Copy Button
        copy_button = QPushButton("📋 Copy Selected Payload")
        copy_button.clicked.connect(self.copy_payload)
        layout.addWidget(copy_button)
        
        widget.setLayout(layout)
        self.load_payloads()
        return widget
    
    def create_results_tab(self) -> QWidget:
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Summary
        layout.addWidget(QLabel("Vulnerability Summary:"))
        self.summary_label = QLabel()
        self.summary_label.setStyleSheet("color: #a0a8c0;")
        layout.addWidget(self.summary_label)
        
        # Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            'Type', 'Severity', 'Title', 'Payloads', 'Remediation'
        ])
        layout.addWidget(self.results_table)
        
        # Export Button
        export_button = QPushButton("💾 Export Results")
        export_button.clicked.connect(self.export_results)
        layout.addWidget(export_button)
        
        widget.setLayout(layout)
        return widget
    
    def create_about_tab(self) -> QWidget:
        """Create about tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setText("""
<h2>APEC Penetration Testing Tool v1.0</h2>

<h3>Features:</h3>
<ul>
    <li>Automated vulnerability scanning</li>
    <li>PayloadsAllTheThings integration</li>
    <li>Multi-threaded scanning</li>
    <li>Comprehensive payload database</li>
    <li>Detailed remediation guidance</li>
    <li>Export results in multiple formats</li>
</ul>

<h3>Supported Vulnerabilities:</h3>
<ul>
    <li>Cross-Site Scripting (XSS)</li>
    <li>SQL Injection</li>
    <li>CSRF Attacks</li>
    <li>Command Injection</li>
    <li>Path Traversal</li>
    <li>XML External Entity (XXE)</li>
    <li>LDAP Injection</li>
    <li>Open Redirect</li>
</ul>

<h3>Legal Notice:</h3>
<p>This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal.</p>

<h3>Credits:</h3>
<p>Payloads sourced from <a href="https://github.com/swisskyrepo/PayloadsAllTheThings">PayloadsAllTheThings</a></p>
        """)
        layout.addWidget(about_text)
        
        widget.setLayout(layout)
        return widget
    
    def start_scan(self):
        """Start vulnerability scan"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return
        
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Scanning...")
        
        depth = self.depth_spinbox.value()
        workers = self.workers_spinbox.value()
        
        self.scanner_thread = ScannerThread(url, depth, workers)
        self.scanner_thread.progress.connect(self.update_status)
        self.scanner_thread.finished.connect(self.scan_finished)
        self.scanner_thread.error.connect(self.scan_error)
        self.scanner_thread.start()
    
    def update_status(self, message: str):
        """Update status label"""
        self.status_label.setText(message)
        self.progress_bar.setValue(min(self.progress_bar.value() + 10, 90))
    
    def scan_finished(self, vulnerabilities: list):
        """Handle scan completion"""
        self.current_vulnerabilities = vulnerabilities
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Scan complete! Found {len(vulnerabilities)} vulnerabilities")
        self.scan_button.setEnabled(True)
        
        # Display results
        self.display_results(vulnerabilities)
        self.display_summary(vulnerabilities)
    
    def scan_error(self, error: str):
        """Handle scan error"""
        self.status_label.setText(f"Error: {error}")
        self.scan_button.setEnabled(True)
        QMessageBox.critical(self, "Scan Error", error)
    
    def display_results(self, vulnerabilities: list):
        """Display scan results in table"""
        self.results_table.setRowCount(len(vulnerabilities))
        
        for row, vuln in enumerate(vulnerabilities):
            self.results_table.setItem(row, 0, QTableWidgetItem(vuln['type']))
            self.results_table.setItem(row, 1, QTableWidgetItem(vuln['severity']))
            self.results_table.setItem(row, 2, QTableWidgetItem(vuln['title']))
            self.results_table.setItem(row, 3, QTableWidgetItem(str(len(vuln.get('payloads', [])))))
            self.results_table.setItem(row, 4, QTableWidgetItem(vuln['remediation']['title']))
        
        # Display detailed results
        results_text = ""
        for vuln in vulnerabilities:
            results_text += f"\n{'='*60}\n"
            results_text += f"[{vuln['severity']}] {vuln['title']}\n"
            results_text += f"Type: {vuln['type']}\n"
            results_text += f"Description: {vuln['description']}\n"
            results_text += f"Payloads: {len(vuln.get('payloads', []))}\n"
            if vuln.get('payloads'):
                results_text += f"Sample Payload: {vuln['payloads'][0]}\n"
        
        self.scan_results_text.setText(results_text)
    
    def display_summary(self, vulnerabilities: list):
        """Display vulnerability summary"""
        summary = {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v['severity'] == 'Critical']),
            'high': len([v for v in vulnerabilities if v['severity'] == 'High']),
            'medium': len([v for v in vulnerabilities if v['severity'] == 'Medium']),
            'low': len([v for v in vulnerabilities if v['severity'] == 'Low']),
        }
        
        summary_text = f"""
Total Vulnerabilities: {summary['total']}
Critical: {summary['critical']}
High: {summary['high']}
Medium: {summary['medium']}
Low: {summary['low']}
        """
        self.summary_label.setText(summary_text)
    
    def load_payloads(self):
        """Load payloads for selected vulnerability type"""
        vuln_type = self.vuln_type_combo.currentText()
        payloads = self.payload_manager.fetch_payloads(vuln_type)
        
        payloads_text = f"Payloads for {vuln_type}:\n\n"
        for i, payload in enumerate(payloads, 1):
            payloads_text += f"{i}. {payload}\n\n"
        
        self.payloads_text.setText(payloads_text)
    
    def copy_payload(self):
        """Copy payload to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.payloads_text.toPlainText())
        QMessageBox.information(self, "Success", "Payload copied to clipboard!")
    
    def export_results(self):
        """Export scan results"""
        if not self.current_vulnerabilities:
            QMessageBox.warning(self, "Error", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "", "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(self.current_vulnerabilities, f, indent=2)
            elif file_path.endswith('.csv'):
                import csv
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Type', 'Severity', 'Title', 'Description'])
                    for vuln in self.current_vulnerabilities:
                        writer.writerow([
                            vuln['type'],
                            vuln['severity'],
                            vuln['title'],
                            vuln['description']
                        ])
            else:
                with open(file_path, 'w') as f:
                    for vuln in self.current_vulnerabilities:
                        f.write(f"\n{'='*60}\n")
                        f.write(f"[{vuln['severity']}] {vuln['title']}\n")
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"Description: {vuln['description']}\n")
                        f.write(f"Payloads: {len(vuln.get('payloads', []))}\n")
            
            QMessageBox.information(self, "Success", f"Results exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")
    
    def apply_styles(self):
        """Apply dark theme styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0e27;
                color: #e0e6ff;
            }
            QWidget {
                background-color: #0a0e27;
                color: #e0e6ff;
            }
            QTabWidget::pane {
                border: 1px solid #00d4ff;
            }
            QTabBar::tab {
                background-color: #1a1f3a;
                color: #a0a8c0;
                padding: 8px 20px;
                border: 1px solid #00d4ff;
            }
            QTabBar::tab:selected {
                background-color: #00d4ff;
                color: #0a0e27;
            }
            QLineEdit, QTextEdit, QSpinBox, QComboBox {
                background-color: #1a1f3a;
                color: #e0e6ff;
                border: 1px solid #00d4ff;
                border-radius: 3px;
                padding: 5px;
            }
            QLabel {
                color: #e0e6ff;
            }
            QTableWidget {
                background-color: #1a1f3a;
                color: #e0e6ff;
                gridline-color: #00d4ff;
            }
            QHeaderView::section {
                background-color: #252d4a;
                color: #00d4ff;
                padding: 5px;
                border: 1px solid #00d4ff;
            }
            QProgressBar {
                background-color: #1a1f3a;
                border: 1px solid #00d4ff;
                border-radius: 3px;
                text-align: center;
                color: #00d4ff;
            }
            QProgressBar::chunk {
                background-color: #00d4ff;
            }
        """)

def main():
    app = QApplication(sys.argv)
    window = APECPentestingTool()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
