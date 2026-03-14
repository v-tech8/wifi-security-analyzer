// Enterprise Dashboard JavaScript

let currentScanId = null;
let currentScanData = null;

document.addEventListener('DOMContentLoaded', function () {
    // Event listeners
    document.getElementById('runScanBtn').addEventListener('click', runComprehensiveScan);

    const generateBtn = document.getElementById('generateReportBtn');
    if (generateBtn) {
        generateBtn.addEventListener('click', generatePDFReport);
    }

    const newScanBtn = document.getElementById('newScanBtn');
    if (newScanBtn) {
        newScanBtn.addEventListener('click', resetDashboard);
    }
});

async function runComprehensiveScan() {
    showLoading(true);

    try {
        const response = await fetch('/api/scan/comprehensive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.success) {
            currentScanId = data.scan_id;
            displayResults(data);
        } else {
            alert('Scan failed: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to perform scan: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayResults(data) {
    // Store scan data for AI advisor
    currentScanData = data;

    // Show results panel
    document.getElementById('resultsPanel').style.display = 'block';

    // Update timestamp
    const timestamp = new Date(data.timestamp).toLocaleString();
    document.getElementById('scanTimestamp').textContent = timestamp;

    // Update risk badge
    updateRiskBadge(data.risk_level, data.security_metrics.overall_risk_score);

    // Update network details
    displayNetworkDetails(data.network_info);

    // Update security metrics
    updateSecurityMetrics(data.security_metrics);

    // Display vulnerabilities
    displayVulnerabilities(data.vulnerabilities);

    // Display threats
    displayThreats(data.threats);

    // Display compliance
    displayCompliance(data.compliance_checks);

    // Display recommendations
    displayRecommendations(data.recommendations);

    // Scroll to results
    document.getElementById('resultsPanel').scrollIntoView({ behavior: 'smooth' });
}

function updateRiskBadge(riskLevel, score) {
    const badge = document.getElementById('riskBadge');
    const scoreEl = document.getElementById('riskScore');
    const labelEl = document.getElementById('riskLabel');

    // Remove existing classes
    badge.classList.remove('safe', 'medium', 'dangerous');

    // Add appropriate class
    badge.classList.add(riskLevel.toLowerCase());

    // Update content
    scoreEl.textContent = score.toFixed(1);
    labelEl.textContent = riskLevel;
}

function displayNetworkDetails(networkInfo) {
    const detailsHtml = `
        <div class="network-detail">
            <strong>SSID</strong>
            <span>${networkInfo.ssid}</span>
        </div>
        <div class="network-detail">
            <strong>BSSID</strong>
            <span>${networkInfo.bssid}</span>
        </div>
        <div class="network-detail">
            <strong>Channel</strong>
            <span>${networkInfo.channel}</span>
        </div>
        <div class="network-detail">
            <strong>Frequency</strong>
            <span>${networkInfo.frequency.toFixed(3)} GHz</span>
        </div>
        <div class="network-detail">
            <strong>Signal Strength</strong>
            <span>${networkInfo.signal_strength} dBm</span>
        </div>
        <div class="network-detail">
            <strong>Encryption</strong>
            <span>${networkInfo.encryption_type}</span>
        </div>
        <div class="network-detail">
            <strong>Cipher</strong>
            <span>${networkInfo.cipher || 'N/A'}</span>
        </div>
        <div class="network-detail">
            <strong>Vendor</strong>
            <span>${networkInfo.vendor || 'Unknown'}</span>
        </div>
    `;

    document.getElementById('networkDetails').innerHTML = detailsHtml;
}

function updateSecurityMetrics(metrics) {
    document.getElementById('encryptionScore').textContent = metrics.encryption_score.toFixed(1);
    document.getElementById('signalScore').textContent = metrics.signal_quality_score.toFixed(1);
    document.getElementById('vulnScore').textContent = metrics.vulnerability_score.toFixed(1);
    document.getElementById('complianceScore').textContent = metrics.compliance_score.toFixed(1);

    // Animate progress bars
    setTimeout(() => {
        document.getElementById('encryptionBar').style.width = metrics.encryption_score + '%';
        document.getElementById('signalBar').style.width = metrics.signal_quality_score + '%';
        document.getElementById('vulnBar').style.width = metrics.vulnerability_score + '%';
        document.getElementById('complianceBar').style.width = metrics.compliance_score + '%';
    }, 100);
}

function displayVulnerabilities(vulnerabilities) {
    const section = document.getElementById('vulnerabilitiesSection');
    const list = document.getElementById('vulnerabilitiesList');

    if (vulnerabilities.length === 0) {
        list.innerHTML = '<p style="color: green; font-weight: bold;">✓ No vulnerabilities detected</p>';
        return;
    }

    let html = '';
    vulnerabilities.forEach(vuln => {
        html += `
            <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
                <div class="vulnerability-header">
                    <span class="vulnerability-title">${vuln.name}</span>
                    <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <div class="vulnerability-details">
                    <p><strong>ID:</strong> ${vuln.id} ${vuln.cve ? '(' + vuln.cve + ')' : ''}</p>
                    <p><strong>CVSS Score:</strong> ${vuln.cvss_score || 'N/A'}</p>
                    <p><strong>Description:</strong> ${vuln.description}</p>
                    <p><strong>Affected:</strong> ${vuln.affected_components.join(', ')}</p>
                    <p><strong>Remediation:</strong> ${vuln.remediation}</p>
                </div>
            </div>
        `;
    });

    list.innerHTML = html;
}

function displayThreats(threats) {
    const section = document.getElementById('threatsSection');
    const list = document.getElementById('threatsList');

    if (threats.length === 0) {
        list.innerHTML = '<p style="color: green; font-weight: bold;">✓ No active threats detected</p>';
        return;
    }

    let html = '';
    threats.forEach(threat => {
        const confidencePct = (threat.confidence * 100).toFixed(0);
        html += `
            <div class="threat-item">
                <div class="threat-header">${threat.threat_type.replace(/_/g, ' ')}</div>
                <p><strong>Confidence:</strong> ${confidencePct}%</p>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${confidencePct}%"></div>
                </div>
                <p>${threat.description}</p>
                <p><strong>Indicators:</strong> ${threat.indicators.join(', ')}</p>
            </div>
        `;
    });

    list.innerHTML = html;
}

function displayCompliance(checks) {
    const list = document.getElementById('complianceList');

    // Group by standard
    const grouped = {};
    checks.forEach(check => {
        if (!grouped[check.standard]) {
            grouped[check.standard] = [];
        }
        grouped[check.standard].push(check);
    });

    let html = '';
    Object.keys(grouped).forEach(standard => {
        html += `<h4 style="margin-top: 20px; color: var(--primary-color);">${standard}</h4>`;

        grouped[standard].forEach(check => {
            const statusClass = check.status.toLowerCase().replace('_', '-');
            html += `
                <div class="compliance-item">
                    <div>
                        <strong>${check.requirement_id}:</strong> ${check.requirement_name}
                        <p style="color: #666; font-size: 0.9rem; margin-top: 5px;">${check.details}</p>
                    </div>
                    <span class="compliance-status ${statusClass}">${check.status.replace('_', ' ')}</span>
                </div>
            `;
        });
    });

    list.innerHTML = html;
}

function displayRecommendations(recommendations) {
    const list = document.getElementById('recommendationsList');

    let html = '';
    recommendations.forEach((rec, index) => {
        html += `
            <div class="recommendation-item">
                ${index + 1}. ${rec}
            </div>
        `;
    });

    list.innerHTML = html;
}

async function generatePDFReport() {
    if (!currentScanId) {
        alert('No scan data available. Please run a scan first.');
        return;
    }

    showLoading(true);

    try {
        const response = await fetch('/api/reports/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ scan_id: currentScanId })
        });

        if (response.ok) {
            // Download the PDF
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `wifi_security_report_${currentScanId.substring(0, 8)}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            alert('PDF report generated successfully!');
        } else {
            const data = await response.json();
            alert('Failed to generate report: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to generate report: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function resetDashboard() {
    document.getElementById('resultsPanel').style.display = 'none';
    currentScanId = null;
    currentScanData = null;

    // Reset AI section
    document.getElementById('aiThinking').style.display = 'none';
    document.getElementById('aiResults').style.display = 'none';
    document.getElementById('aiSuggestionsList').innerHTML = '';
    document.getElementById('aiSummary').textContent = '';
    document.getElementById('aiSourceBadge').textContent = '';
    document.getElementById('getAIBtn').disabled = false;

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─── AI Advisor ──────────────────────────────────────────────────────────────

async function getAISuggestions() {
    if (!currentScanData) {
        alert('Please run a scan first to get AI suggestions.');
        return;
    }

    const btn = document.getElementById('getAIBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Analyzing...</span>';

    document.getElementById('aiThinking').style.display = 'flex';
    document.getElementById('aiResults').style.display = 'none';

    try {
        const response = await fetch('/api/ai/suggestions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentScanData)
        });

        const data = await response.json();

        document.getElementById('aiThinking').style.display = 'none';

        if (data.success) {
            displayAISuggestions(data);
        } else {
            showAIError('Could not fetch AI suggestions: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        document.getElementById('aiThinking').style.display = 'none';
        showAIError('Connection error: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-sparkles"></i> <span>Refresh AI Suggestions</span>';
    }
}

function displayAISuggestions(data) {
    const resultsEl = document.getElementById('aiResults');
    const summaryEl = document.getElementById('aiSummary');
    const listEl = document.getElementById('aiSuggestionsList');
    const badgeEl = document.getElementById('aiSourceBadge');

    // Summary
    summaryEl.textContent = data.summary || '';

    // Source badge
    if (data.source === 'gemini') {
        badgeEl.innerHTML = '<i class="fas fa-robot"></i> Powered by Google Gemini AI';
        badgeEl.className = 'ai-source-badge gemini';
    } else {
        badgeEl.innerHTML = '<i class="fas fa-microchip"></i> Smart Rule-Based Analysis';
        badgeEl.className = 'ai-source-badge rule-based';
    }

    // Build suggestion cards first (hidden)
    listEl.innerHTML = '';
    (data.suggestions || []).forEach((suggestion, idx) => {
        const item = document.createElement('div');
        item.className = 'ai-suggestion-item';
        item.style.opacity = '0';
        item.style.transform = 'translateY(12px)';
        item.innerHTML = `
            <div class="ai-suggestion-num">${idx + 1}</div>
            <div class="ai-suggestion-text"></div>
        `;
        listEl.appendChild(item);
    });

    resultsEl.style.display = 'block';
    resultsEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Animate each card then typewrite text
    (data.suggestions || []).forEach((suggestion, idx) => {
        const item = listEl.children[idx];
        const textEl = item.querySelector('.ai-suggestion-text');

        setTimeout(() => {
            item.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            item.style.opacity = '1';
            item.style.transform = 'translateY(0)';
            typewrite(textEl, suggestion, 18);
        }, idx * 180);
    });
}

function typewrite(el, text, speed) {
    let i = 0;
    el.textContent = '';
    const timer = setInterval(() => {
        el.textContent += text[i];
        i++;
        if (i >= text.length) clearInterval(timer);
    }, speed);
}

function showAIError(msg) {
    const resultsEl = document.getElementById('aiResults');
    const listEl = document.getElementById('aiSuggestionsList');
    document.getElementById('aiSummary').textContent = '';
    document.getElementById('aiSourceBadge').textContent = '';
    listEl.innerHTML = `<div class="ai-error"><i class="fas fa-circle-exclamation"></i> ${msg}</div>`;
    resultsEl.style.display = 'block';
}


function showLoading(show) {
    document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
}
