# Enterprise Wi-Fi Security Analysis Platform

<div align="center">

![Security Analysis](https://img.shields.io/badge/Security-Analysis-blue)
![Python](https://img.shields.io/badge/Python-3.14-green)
![Flask](https://img.shields.io/badge/Flask-3.1.0-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow)

**Professional-grade Wi-Fi security analysis platform with ML-powered risk assessment, compliance checking, and enterprise reporting**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [API](#api-endpoints) • [Screenshots](#screenshots)

</div>

---

## 🚀 Features

### Core Capabilities
- **🔍 Automated Security Scanning** - One-click Wi-Fi network analysis
- **🤖 Machine Learning Risk Assessment** - Random Forest classifier for threat detection
- **📊 Comprehensive Dashboard** - Enterprise-grade Security Operations Center interface
- **📄 Professional PDF Reports** - Executive-ready security analysis documents
- **✅ Compliance Checking** - Automated validation against PCI-DSS, HIPAA, ISO 27001
- **📈 Historical Tracking** - SQLite-based scan history and trend analysis
- **🛡️ Vulnerability Detection** - CVE database with KRACK, DragonBlood, FragAttacks
- **⚡ Threat Intelligence** - Evil twin, deauth attack, and MITM detection

### Enterprise Features
- Multi-standard compliance reporting (PCI-DSS 4.0, HIPAA, ISO 27001:2022)
- Weighted risk scoring algorithm (0-100 scale)
- Professional PDF generation with charts and visualizations
- RESTful API for integration
- Responsive web interface
- Real-time security metrics

---

## 📋 Requirements

- Python 3.14+
- macOS / Linux (Windows with WSL)
- 2GB RAM minimum
- Modern web browser

---

## 🔧 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/wifi-security-analyzer.git
cd wifi-security-analyzer
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python3 app.py
```

The application will be available at:
- **Quick Scan**: http://127.0.0.1:5001/
- **Enterprise Dashboard**: http://127.0.0.1:5001/dashboard

---

## 💻 Usage

### Quick Scan
1. Navigate to http://127.0.0.1:5001/
2. Click "Run Security Scan" for automated analysis
3. View instant risk assessment results

### Enterprise Dashboard
1. Navigate to http://127.0.0.1:5001/dashboard
2. Click "Run Comprehensive Scan"
3. Review detailed security metrics, vulnerabilities, threats, and compliance status
4. Generate PDF report for documentation

### Manual Analysis
1. Use the "Advanced: Manual Entry" option
2. Input network parameters manually
3. Analyze custom network configurations

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Quick scan interface |
| `/dashboard` | GET | Enterprise dashboard |
| `/scan_and_predict` | POST | Automated scan and prediction |
| `/api/scan/comprehensive` | POST | Full security analysis |
| `/api/reports/generate` | POST | Generate PDF report |
| `/api/reports/history` | GET | Retrieve scan history |
| `/api/analytics/trends` | GET | Get trend analytics |

---

## 📊 Risk Scoring

The platform uses a weighted multi-factor risk scoring system:

- **Encryption Strength** (30%): WPA3 = 100, WPA2-AES = 85, WEP = 10, Open = 0
- **Signal Quality** (15%): Based on dBm signal strength
- **Vulnerability Count** (25%): Inverse of detected vulnerabilities
- **Compliance Score** (20%): Percentage of requirements met
- **Threat Indicators** (10%): Inverse of threat confidence levels

**Risk Levels:**
- 🟢 **SAFE** (0-30): Network is secure
- 🟡 **MEDIUM** (31-60): Some security concerns
- 🔴 **DANGEROUS** (61-100): Critical security issues

---

## 🔒 Compliance Standards

### PCI-DSS 4.0 (Payment Card Industry)
- Requirement 4.2.1: Strong cryptography and security protocols
- Requirement 2.2.4: Configure system security parameters
- Requirement 11.2.1: Perform quarterly wireless analyzer scans

### HIPAA Security Rule (Healthcare)
- 164.312(a)(2)(iv): Encryption and Decryption
- 164.308(a)(1)(ii)(D): Information System Activity Review
- 164.312(e)(1): Transmission Security

### ISO/IEC 27001:2022 (Information Security)
- A.8.24: Use of cryptography
- A.8.22: Segregation of networks
- A.8.20: Networks security

---

## 🛡️ Vulnerability Database

The system detects known vulnerabilities including:

- **KRACK** (CVE-2017-13077): Key Reinstallation Attack on WPA2
- **DragonBlood** (CVE-2019-13377): WPA3 Dragonfly Handshake vulnerability
- **FragAttacks** (CVE-2020-24586): Fragmentation and Aggregation Attacks
- **Weak Encryption**: Automatic detection of WEP, WPA, and Open networks

---

## 📸 Screenshots

### Quick Scan Interface
Professional one-click security analysis with instant results.

### Enterprise Dashboard
Comprehensive Security Operations Center with real-time metrics, vulnerability tracking, and compliance monitoring.

### PDF Reports
Executive-ready security analysis reports with charts, findings, and recommendations.

---

## 🏗️ Project Structure

```
wifi-security-analyzer/
├── app.py                      # Main Flask application
├── config.py                   # Configuration & standards
├── models.py                   # Data models
├── database.py                 # Database management
├── security_analyzer.py        # Security analysis engine
├── report_generator.py         # PDF report generation
├── scan_wifi.py               # Wi-Fi scanning utility
├── train_model.py             # ML model training
├── requirements.txt           # Python dependencies
├── model/
│   └── wifi_risk_model.pkl    # Trained ML model
├── templates/
│   ├── index.html             # Quick scan interface
│   └── dashboard.html         # Enterprise dashboard
├── static/
│   ├── css/
│   │   ├── style.css          # Quick scan styles
│   │   └── dashboard.css      # Dashboard styles
│   └── js/
│       └── dashboard.js       # Dashboard interactivity
├── reports/                    # Generated PDF reports
└── dataset/                    # Training data
```

---

## 🔬 Technology Stack

- **Backend**: Flask, Python 3.14
- **Database**: SQLite
- **Machine Learning**: Scikit-learn (Random Forest)
- **PDF Generation**: ReportLab
- **Charts**: Matplotlib
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Icons**: Font Awesome 6
- **Fonts**: Inter

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Vrunda Dalsaniya**

---

## 🙏 Acknowledgments

- Font Awesome for professional icons
- ReportLab for PDF generation
- Scikit-learn for machine learning capabilities
- Flask community for the excellent web framework

---

## 📧 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

<div align="center">

**Built with ❤️ for enterprise security professionals**

⭐ Star this repository if you find it helpful!

</div>
