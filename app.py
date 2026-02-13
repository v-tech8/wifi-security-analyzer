from flask import Flask, request, jsonify, render_template, send_file
import pickle
import numpy as np
from datetime import datetime
import os

app = Flask(__name__)

# Load trained model
model = pickle.load(open("model/wifi_risk_model.pkl", "rb"))

# Import enterprise modules
import scan_wifi
from security_analyzer import SecurityAnalyzer
from report_generator import ReportGenerator
from database import Database
import config

# Initialize enterprise components
security_analyzer = SecurityAnalyzer()
report_generator = ReportGenerator()
db = Database()

risk_map = {
    0: "SAFE 🟢",
    1: "MEDIUM ⚠️",
    2: "DANGEROUS 🔴"
}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    """Enterprise dashboard view"""
    recent_scans = db.get_recent_scans(limit=5)
    return render_template("dashboard.html", recent_scans=recent_scans)

@app.route("/scan_and_predict", methods=["POST"])
def scan_and_predict():
    """Quick scan endpoint (original functionality)"""
    wifi_data = scan_wifi.get_wifi_info()
    
    features = np.array([[
        wifi_data["encryption"],
        wifi_data["signal_strength"],
        wifi_data["channel"],
        wifi_data["ssid_similarity"],
        wifi_data["packet_anomaly"]
    ]])
    
    prediction = model.predict(features)[0]
    result = risk_map[prediction]
    
    return jsonify({
        "wifi_data": wifi_data,
        "result": result
    })

@app.route("/api/scan/comprehensive", methods=["POST"])
def comprehensive_scan():
    """
    Enterprise-grade comprehensive security analysis
    Returns detailed security report with vulnerabilities, threats, and compliance
    """
    try:
        # Get Wi-Fi data
        wifi_data = scan_wifi.get_wifi_info()
        
        # Perform comprehensive security analysis
        scan_result = security_analyzer.analyze_network(wifi_data)
        
        # Save to database
        db.save_scan(scan_result.to_dict())
        
        # Return detailed results
        return jsonify({
            "success": True,
            "scan_id": scan_result.scan_id,
            "timestamp": scan_result.timestamp.isoformat(),
            "network_info": scan_result.network_info.to_dict(),
            "risk_level": scan_result.risk_level.value,
            "security_metrics": scan_result.security_metrics.to_dict(),
            "vulnerabilities": [v.to_dict() for v in scan_result.vulnerabilities],
            "threats": [t.to_dict() for t in scan_result.threats],
            "compliance_checks": [c.to_dict() for c in scan_result.compliance_checks],
            "recommendations": scan_result.recommendations
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/reports/generate", methods=["POST"])
def generate_report():
    """
    Generate professional PDF report
    Expects: {"scan_id": "..."}
    Returns: PDF file download
    """
    try:
        data = request.json
        scan_id = data.get("scan_id")
        
        if not scan_id:
            return jsonify({"success": False, "error": "scan_id required"}), 400
        
        # Retrieve scan data
        scan_data = db.get_scan(scan_id)
        if not scan_data:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        
        # Reconstruct scan result object
        from models import (
            ScanResult, NetworkInfo, SecurityMetrics, Vulnerability,
            ThreatIndicator, ComplianceCheck, RiskLevel, ComplianceStatus
        )
        
        network_info = NetworkInfo(**scan_data['network_info'])
        security_metrics = SecurityMetrics(**scan_data['security_metrics'])
        
        vulnerabilities = [Vulnerability(**v) for v in scan_data['vulnerabilities']]
        threats = [ThreatIndicator(**{**t, 'timestamp': datetime.fromisoformat(t['timestamp'])}) 
                  for t in scan_data['threats']]
        compliance_checks = [ComplianceCheck(**{**c, 'status': ComplianceStatus(c['status'])}) 
                           for c in scan_data['compliance_checks']]
        
        scan_result = ScanResult(
            scan_id=scan_data['scan_id'],
            timestamp=datetime.fromisoformat(scan_data['timestamp']),
            network_info=network_info,
            risk_level=RiskLevel(scan_data['risk_level']),
            security_metrics=security_metrics,
            vulnerabilities=vulnerabilities,
            threats=threats,
            compliance_checks=compliance_checks,
            recommendations=scan_data['recommendations']
        )
        
        # Generate PDF
        report_filename = f"wifi_security_report_{scan_id[:8]}.pdf"
        report_path = os.path.join("reports", report_filename)
        
        # Create reports directory if it doesn't exist
        os.makedirs("reports", exist_ok=True)
        
        success = report_generator.generate_report(scan_result, report_path)
        
        if success:
            return send_file(
                report_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=report_filename
            )
        else:
            return jsonify({"success": False, "error": "Report generation failed"}), 500
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/reports/history", methods=["GET"])
def get_report_history():
    """Get historical scan reports"""
    try:
        limit = request.args.get('limit', 10, type=int)
        scans = db.get_recent_scans(limit=limit)
        return jsonify({
            "success": True,
            "scans": scans
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/analytics/trends", methods=["GET"])
def get_trends():
    """Get trend analytics data"""
    try:
        days = request.args.get('days', 30, type=int)
        trends = db.get_trend_data(days=days)
        return jsonify({
            "success": True,
            "trends": trends
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/ui-predict", methods=["POST"])
def ui_predict():
    """Original UI prediction endpoint"""
    data = request.form

    features = np.array([[
        int(data["encryption"]),
        int(data["signal_strength"]),
        int(data["channel"]),
        int(data["ssid_similarity"]),
        int(data["packet_anomaly"])
    ]])

    prediction = model.predict(features)[0]
    return render_template("index.html", result=risk_map[prediction])

@app.route("/predict", methods=["POST"])
def api_predict():
    """Original API prediction endpoint"""
    data = request.json

    features = np.array([[
        data["encryption"],
        data["signal_strength"],
        data["channel"],
        data["ssid_similarity"],
        data["packet_anomaly"]
    ]])

    prediction = model.predict(features)[0]
    return jsonify({"WiFi Risk Level": risk_map[prediction]})

if __name__ == "__main__":
    app.run(debug=True, port=5001, host='0.0.0.0')

