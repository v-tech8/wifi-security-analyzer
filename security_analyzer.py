"""
Advanced Security Analysis Engine for Wi-Fi Networks
"""
import re
from datetime import datetime
from typing import List, Dict, Tuple
import uuid
import config
from models import (
    NetworkInfo, Vulnerability, ThreatIndicator, ComplianceCheck,
    SecurityMetrics, ScanResult, RiskLevel, ComplianceStatus
)

class SecurityAnalyzer:
    """Comprehensive security analysis engine"""
    
    def __init__(self):
        self.known_vulnerabilities = config.KNOWN_VULNERABILITIES
        self.compliance_standards = config.COMPLIANCE_STANDARDS
        self.encryption_ratings = config.ENCRYPTION_RATINGS
        self.threat_patterns = config.THREAT_PATTERNS
    
    def analyze_network(self, network_data: Dict) -> ScanResult:
        """
        Perform comprehensive security analysis on network
        
        Args:
            network_data: Dictionary containing network information
            
        Returns:
            ScanResult object with complete analysis
        """
        # Create network info object
        network_info = self._parse_network_info(network_data)
        
        # Perform individual analyses
        encryption_score = self._analyze_encryption(network_info)
        signal_score = self._analyze_signal_quality(network_info)
        vulnerabilities = self._detect_vulnerabilities(network_info)
        threats = self._detect_threats(network_info, network_data)
        compliance_checks = self._check_compliance(network_info, vulnerabilities)
        
        # Calculate scores
        vulnerability_score = self._calculate_vulnerability_score(vulnerabilities)
        compliance_score = self._calculate_compliance_score(compliance_checks)
        threat_score = self._calculate_threat_score(threats)
        
        # Calculate overall risk
        security_metrics = SecurityMetrics(
            encryption_score=encryption_score,
            signal_quality_score=signal_score,
            vulnerability_score=vulnerability_score,
            compliance_score=compliance_score,
            threat_score=threat_score,
            overall_risk_score=self._calculate_overall_risk(
                encryption_score, signal_score, vulnerability_score,
                compliance_score, threat_score
            )
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(security_metrics.overall_risk_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            network_info, vulnerabilities, threats, compliance_checks
        )
        
        # Create scan result
        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            network_info=network_info,
            risk_level=risk_level,
            security_metrics=security_metrics,
            vulnerabilities=vulnerabilities,
            threats=threats,
            compliance_checks=compliance_checks,
            recommendations=recommendations
        )
        
        return scan_result
    
    def _parse_network_info(self, data: Dict) -> NetworkInfo:
        """Parse network data into NetworkInfo object"""
        encryption_type = self._determine_encryption_type(data.get('encryption', 0))
        
        return NetworkInfo(
            ssid=data.get('ssid', 'Unknown'),
            bssid=data.get('bssid', 'Unknown'),
            channel=data.get('channel', 0),
            frequency=self._channel_to_frequency(data.get('channel', 0)),
            signal_strength=data.get('signal_strength', -100),
            encryption_type=encryption_type,
            cipher=self._determine_cipher(encryption_type),
            authentication=self._determine_auth_method(encryption_type),
            vendor=self._lookup_vendor(data.get('bssid', ''))
        )
    
    def _determine_encryption_type(self, encryption_code: int) -> str:
        """Map encryption code to type"""
        encryption_map = {
            0: 'Open',
            1: 'WEP',
            2: 'WPA',
            3: 'WPA2-TKIP',
            4: 'WPA2-AES',
            5: 'WPA3'
        }
        return encryption_map.get(encryption_code, 'Unknown')
    
    def _determine_cipher(self, encryption_type: str) -> str:
        """Determine cipher suite"""
        if 'AES' in encryption_type or 'WPA3' in encryption_type:
            return 'AES-CCMP'
        elif 'TKIP' in encryption_type:
            return 'TKIP'
        elif 'WEP' in encryption_type:
            return 'RC4'
        return 'None'
    
    def _determine_auth_method(self, encryption_type: str) -> str:
        """Determine authentication method"""
        if 'WPA3' in encryption_type:
            return 'SAE (Simultaneous Authentication of Equals)'
        elif 'WPA' in encryption_type:
            return 'PSK (Pre-Shared Key)'
        elif 'WEP' in encryption_type:
            return 'Open System / Shared Key'
        return 'Open'
    
    def _channel_to_frequency(self, channel: int) -> float:
        """Convert channel number to frequency (GHz)"""
        if 1 <= channel <= 14:
            return 2.407 + (channel * 0.005)  # 2.4 GHz band
        elif 36 <= channel <= 165:
            return 5.0 + ((channel - 36) * 0.005)  # 5 GHz band
        return 0.0
    
    def _lookup_vendor(self, bssid: str) -> str:
        """Lookup vendor from MAC address (simplified)"""
        # In production, use OUI database lookup
        oui_map = {
            '00:1A:2B': 'Cisco Systems',
            '00:1B:63': 'Netgear',
            '00:1E:58': 'TP-Link',
            '00:24:A5': 'Ubiquiti Networks',
            '00:50:56': 'VMware'
        }
        oui = ':'.join(bssid.split(':')[:3]).upper()
        return oui_map.get(oui, 'Unknown Vendor')
    
    def _analyze_encryption(self, network_info: NetworkInfo) -> float:
        """Analyze encryption strength (0-100)"""
        rating = self.encryption_ratings.get(network_info.encryption_type, {'score': 50})
        return float(rating['score'])
    
    def _analyze_signal_quality(self, network_info: NetworkInfo) -> float:
        """Analyze signal quality (0-100)"""
        signal = network_info.signal_strength
        
        # Convert dBm to quality score
        if signal >= -50:
            return 100.0
        elif signal >= -60:
            return 85.0
        elif signal >= -70:
            return 70.0
        elif signal >= -80:
            return 50.0
        else:
            return 30.0
    
    def _detect_vulnerabilities(self, network_info: NetworkInfo) -> List[Vulnerability]:
        """Detect known vulnerabilities"""
        vulnerabilities = []
        
        # Check for known CVEs
        for vuln_id, vuln_data in self.known_vulnerabilities.items():
            if network_info.encryption_type in vuln_data['affects']:
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name=vuln_data['name'],
                    severity=vuln_data['severity'],
                    cve=vuln_data['cve'],
                    description=vuln_data['description'],
                    affected_components=[network_info.encryption_type],
                    remediation=self._get_remediation(vuln_id),
                    cvss_score=self._get_cvss_score(vuln_data['severity'])
                ))
        
        # Check for weak encryption
        if network_info.encryption_type in ['Open', 'WEP', 'WPA']:
            vulnerabilities.append(Vulnerability(
                id='WEAK_ENCRYPTION',
                name='Weak or No Encryption',
                severity='Critical',
                description=f'{network_info.encryption_type} provides insufficient security',
                affected_components=['Encryption Layer'],
                remediation='Upgrade to WPA2-AES or WPA3',
                cvss_score=9.0
            ))
        
        return vulnerabilities
    
    def _detect_threats(self, network_info: NetworkInfo, raw_data: Dict) -> List[ThreatIndicator]:
        """Detect potential threats"""
        threats = []
        
        # Evil Twin Detection (simplified)
        if raw_data.get('ssid_similarity', 0) > 80:
            threats.append(ThreatIndicator(
                threat_type='evil_twin',
                confidence=0.7,
                description='Possible Evil Twin attack - similar SSID detected',
                indicators=['high_ssid_similarity', 'different_bssid']
            ))
        
        # Deauth Attack Detection
        if raw_data.get('packet_anomaly', 0) > 70:
            threats.append(ThreatIndicator(
                threat_type='deauth_attack',
                confidence=0.6,
                description='Unusual packet patterns detected',
                indicators=['high_packet_anomaly', 'connection_instability']
            ))
        
        # Weak Signal Warning (potential MITM)
        if network_info.signal_strength < -80:
            threats.append(ThreatIndicator(
                threat_type='weak_signal',
                confidence=0.4,
                description='Very weak signal may indicate distance or interference',
                indicators=['poor_signal_strength']
            ))
        
        return threats
    
    def _check_compliance(self, network_info: NetworkInfo, 
                         vulnerabilities: List[Vulnerability]) -> List[ComplianceCheck]:
        """Check compliance with standards"""
        compliance_checks = []
        
        for standard_name, standard in self.compliance_standards.items():
            for req in standard['requirements']:
                status, details = self._evaluate_requirement(
                    req['check'], network_info, vulnerabilities
                )
                
                compliance_checks.append(ComplianceCheck(
                    standard=standard_name,
                    requirement_id=req['id'],
                    requirement_name=req['description'],
                    status=status,
                    details=details
                ))
        
        return compliance_checks
    
    def _evaluate_requirement(self, check_type: str, network_info: NetworkInfo,
                             vulnerabilities: List[Vulnerability]) -> Tuple[ComplianceStatus, str]:
        """Evaluate specific compliance requirement"""
        if check_type == 'encryption_wpa3_or_wpa2_aes':
            if network_info.encryption_type in ['WPA3', 'WPA2-AES']:
                return ComplianceStatus.COMPLIANT, f'Using {network_info.encryption_type}'
            else:
                return ComplianceStatus.NON_COMPLIANT, f'Using {network_info.encryption_type} instead of WPA2-AES/WPA3'
        
        elif check_type == 'strong_encryption_enabled':
            if network_info.encryption_type in ['WPA3', 'WPA2-AES']:
                return ComplianceStatus.COMPLIANT, 'Strong encryption enabled'
            else:
                return ComplianceStatus.NON_COMPLIANT, 'Weak encryption detected'
        
        elif check_type == 'rogue_ap_detection':
            # Simplified check
            return ComplianceStatus.PARTIAL, 'Manual verification required'
        
        else:
            return ComplianceStatus.NOT_APPLICABLE, 'Check not implemented'
    
    def _calculate_vulnerability_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate vulnerability score (0-100, lower is better)"""
        if not vulnerabilities:
            return 100.0
        
        severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2}
        total_weight = sum(severity_weights.get(v.severity, 1) for v in vulnerabilities)
        
        # Invert score (more vulns = lower score)
        score = max(0, 100 - (total_weight * 5))
        return float(score)
    
    def _calculate_compliance_score(self, checks: List[ComplianceCheck]) -> float:
        """Calculate compliance score (0-100)"""
        if not checks:
            return 50.0
        
        status_scores = {
            ComplianceStatus.COMPLIANT: 100,
            ComplianceStatus.PARTIAL: 50,
            ComplianceStatus.NON_COMPLIANT: 0,
            ComplianceStatus.NOT_APPLICABLE: 100
        }
        
        total = sum(status_scores.get(check.status, 50) for check in checks)
        return float(total / len(checks))
    
    def _calculate_threat_score(self, threats: List[ThreatIndicator]) -> float:
        """Calculate threat score (0-100, lower is better)"""
        if not threats:
            return 100.0
        
        # Weight by confidence
        total_confidence = sum(t.confidence for t in threats)
        score = max(0, 100 - (total_confidence * 30))
        return float(score)
    
    def _calculate_overall_risk(self, encryption: float, signal: float,
                               vulnerability: float, compliance: float,
                               threat: float) -> float:
        """Calculate weighted overall risk score"""
        weights = config.RISK_WEIGHTS
        
        overall = (
            encryption * weights['encryption_strength'] +
            signal * weights['signal_quality'] +
            vulnerability * weights['vulnerability_count'] +
            compliance * weights['compliance_score'] +
            threat * weights['threat_indicators']
        )
        
        return round(overall, 2)
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        thresholds = config.RISK_THRESHOLDS
        
        if thresholds['safe'][0] <= score <= thresholds['safe'][1]:
            return RiskLevel.SAFE
        elif thresholds['medium'][0] <= score <= thresholds['medium'][1]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.DANGEROUS
    
    def _generate_recommendations(self, network_info: NetworkInfo,
                                 vulnerabilities: List[Vulnerability],
                                 threats: List[ThreatIndicator],
                                 compliance_checks: List[ComplianceCheck]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Encryption recommendations
        if network_info.encryption_type in ['Open', 'WEP', 'WPA']:
            recommendations.append(
                f"🔴 CRITICAL: Upgrade from {network_info.encryption_type} to WPA3 or WPA2-AES immediately"
            )
        elif network_info.encryption_type == 'WPA2-TKIP':
            recommendations.append(
                "⚠️ WARNING: Upgrade from WPA2-TKIP to WPA2-AES for better security"
            )
        
        # Signal recommendations
        if network_info.signal_strength < -70:
            recommendations.append(
                "📡 Consider moving closer to access point or using a Wi-Fi extender"
            )
        
        # Vulnerability recommendations
        for vuln in vulnerabilities:
            if vuln.remediation:
                recommendations.append(f"🔧 {vuln.name}: {vuln.remediation}")
        
        # Threat recommendations
        for threat in threats:
            if threat.confidence > 0.6:
                recommendations.append(
                    f"⚡ {threat.threat_type.upper()}: {threat.description} - Verify network authenticity"
                )
        
        # Compliance recommendations
        non_compliant = [c for c in compliance_checks if c.status == ComplianceStatus.NON_COMPLIANT]
        if non_compliant:
            recommendations.append(
                f"📋 Address {len(non_compliant)} compliance gaps for regulatory requirements"
            )
        
        # General recommendations
        recommendations.append("🔐 Enable network encryption if not already enabled")
        recommendations.append("🔄 Regularly update router firmware")
        recommendations.append("🔑 Use strong, unique passwords for Wi-Fi access")
        
        return recommendations
    
    def _get_remediation(self, vuln_id: str) -> str:
        """Get remediation steps for vulnerability"""
        remediations = {
            'KRACK': 'Update router firmware and client devices to patched versions',
            'DragonBlood': 'Update to latest WPA3 implementation with security patches',
            'FragAttacks': 'Apply vendor security patches and disable frame aggregation if possible'
        }
        return remediations.get(vuln_id, 'Consult vendor security advisories')
    
    def _get_cvss_score(self, severity: str) -> float:
        """Map severity to CVSS score"""
        scores = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }
        return scores.get(severity, 5.0)
