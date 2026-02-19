# Epic Scanning Tool Tool

A powerful professional-grade penetration testing application built with Python and PyQt6, featuring comprehensive vulnerability scanning with integrated PayloadsAllTheThings database.

## 🌟 Key Features

**Advanced Vulnerability Detection:**
- Cross-Site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Command Injection
- Path Traversal
- XML External Entity (XXE)
- LDAP Injection
- Open Redirect

**PayloadsAllTheThings Integration:**
- Automatic payload fetching from official repository
- Comprehensive payload database for each vulnerability type
- Local caching for offline use
- Search and filter capabilities

**Professional Features:**
- Multi-threaded scanning engine
- Real-time progress tracking
- Detailed vulnerability reports
- Payload display and copying
- Export results (JSON, CSV, TXT)
- Dark-themed professional UI

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Internet connection (for initial payload download)

### Setup

1. **Clone or download the project:**
```bash
cd EpicScanningTool
```

2. **Create virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Run the application:**
```bash
python main.py
```

## 📋 Usage Guide

### Basic Scanning

1. **Enter Target URL:**
   - Go to the "Scanner" tab
   - Enter the target website URL (e.g., https://example.com)

2. **Configure Scan:**
   - Set scan depth (1-5, higher = more thorough)
   - Set number of workers (threads) for parallel scanning
   - Click "Start Scan"

3. **Review Results:**
   - Check the "Results" tab for vulnerability summary
   - View detailed findings in the results table
   - Each vulnerability shows type, severity, and remediation

4. **Export Results:**
   - Click "Export Results" to save findings
   - Choose format: JSON, CSV, or TXT

### Payload Management

1. **Browse Payloads:**
   - Go to "Payloads" tab
   - Select vulnerability type from dropdown
   - View all available payloads for that type

2. **Copy Payloads:**
   - Click "Copy Selected Payload"
   - Paste into your testing tools

3. **Payload Database:**
   - Automatically fetches from PayloadsAllTheThings
   - Cached locally for offline use
   - Updated on each application run

## 🔧 Configuration

### Scan Depth Levels
- **Level 1:** Quick scan (30-60 seconds)
- **Level 2:** Standard scan (1-2 minutes)
- **Level 3:** Deep scan (2-5 minutes)
- **Level 4:** Very deep scan (5-10 minutes)
- **Level 5:** Exhaustive scan (10+ minutes)

### Threading
- Adjust from 1-16 worker threads
- More threads = faster but higher resource usage
- Recommended: 4-8 threads for most targets

## 📁 Project Structure

```
EpicScanningTool/
├── main.py              # Main PyQt6 application
├── scanner.py           # Vulnerability scanning engine
├── payload_manager.py   # PayloadsAllTheThings integration
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## 🛡️ Security Features

**Local Processing:**
- All scanning performed locally
- No data sent to external servers
- Complete privacy and control

**Payload Management:**
- Payloads fetched from official PayloadsAllTheThings
- Local caching for offline use
- Automatic updates on startup

**Comprehensive Detection:**
- Multiple scanning techniques
- Pattern matching and analysis
- Header inspection
- Form analysis

## 📊 Supported Vulnerability Types

| Vulnerability | Severity | Detection Method |
|---|---|---|
| XSS | High | Pattern matching, form analysis |
| SQL Injection | Critical | Pattern matching, query analysis |
| CSRF | Medium | Form token detection |
| Command Injection | Critical | System call detection |
| Path Traversal | High | Path pattern analysis |
| XXE | High | XML entity detection |
| LDAP Injection | High | LDAP query analysis |
| Open Redirect | Medium | URL parameter analysis |

## 🔄 Payload Sources

Payloads are sourced from the official PayloadsAllTheThings repository:
- **Repository:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **License:** MIT
- **Update Frequency:** Automatic on application startup

## 💾 Data Storage

**Payload Cache Location:**
- Linux/Mac: `~/.EpicScanningTool/payloads/`
- Windows: `%USERPROFILE%\.EpicScanningTool\payloads\`

**Cache Contents:**
- `payloads_cache.json` - Cached payloads from PayloadsAllTheThings

## 📤 Export Formats

### JSON Export
Complete structured data including all vulnerabilities and payloads
```json
{
  "type": "XSS",
  "severity": "High",
  "title": "Cross-Site Scripting Vulnerability",
  "payloads": ["<script>alert('XSS')</script>", ...]
}
```

### CSV Export
Tabular format suitable for spreadsheet analysis
```
Type,Severity,Title,Description
XSS,High,Cross-Site Scripting,JavaScript injection vulnerability
```

### TXT Export
Human-readable format with detailed descriptions

## 🐛 Troubleshooting

### Application Won't Start
```bash
# Verify Python version
python --version  # Should be 3.8+

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Try running with verbose output
python -u main.py
```

### Payload Download Fails
- Check internet connection
- Verify GitHub is accessible
- Payloads will use defaults if download fails
- Check cache at `~/.EpicScanningTool/payloads/`

### Slow Scanning
- Reduce scan depth
- Reduce number of workers
- Check target server availability
- Increase timeout if needed

### Memory Issues
- Reduce number of worker threads
- Scan smaller targets
- Close other applications

## 🔐 Legal & Ethical Notice

**Important:** This tool is designed for authorized security testing only.

- ✅ Only scan websites/systems you own or have explicit permission to test
- ✅ Obtain written authorization before any security testing
- ✅ Comply with all applicable laws and regulations
- ✅ Use responsibly and ethically

**Unauthorized access to computer systems is illegal.**

## 📚 Learning Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- Web Security Academy: https://portswigger.net/web-security

## 🚀 Advanced Usage

### Command Line Integration
```bash
# Run with specific target
python main.py

# The tool can be integrated into security workflows
```

### Payload Customization
Modify `payload_manager.py` to add custom payloads:
```python
'custom_type': [
    'custom_payload_1',
    'custom_payload_2',
]
```

### Extending Vulnerability Detection
Add new scan methods to `scanner.py`:
```python
def _scan_custom_vuln(self, html: str, url: str) -> List[Dict]:
    # Your detection logic here
    pass
```

## 📈 Performance Tips

1. **Optimize Threading:**
   - Use 4-8 workers for most targets
   - Increase for powerful machines
   - Decrease for limited resources

2. **Reduce Scan Depth:**
   - Start with depth 1-2
   - Increase only if needed
   - Higher depth = longer scans

3. **Target Selection:**
   - Test on smaller sites first
   - Avoid high-traffic production systems
   - Schedule scans during off-peak hours

## 🤝 Contributing

To contribute improvements:
1. Test thoroughly
2. Follow existing code style
3. Add documentation
4. Submit pull requests

## 📝 Changelog

### Version 1.0
- Initial release
- PayloadsAllTheThings integration
- 8 vulnerability types
- PyQt6 GUI
- Export functionality

## 📞 Support

For issues or questions:
1. Check this README
2. Review error messages
3. Check payload cache
4. Verify internet connection
5. Reinstall dependencies

## 📄 License

This project is provided as-is for authorized security testing purposes.

## 🙏 Acknowledgments

- **PayloadsAllTheThings:** Comprehensive payload database
- **PyQt6:** Professional GUI framework
- **BeautifulSoup:** HTML parsing
- **Requests:** HTTP library

---

**Epic Scanning Tool Tool v1.0**
Professional Security Scanning with PayloadsAllTheThings Integration
