"""
Data models for Wi-Fi Security Analysis System
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum

class RiskLevel(Enum):
    """Risk level enumeration"""
    SAFE = "SAFE"
    MEDIUM = "MEDIUM"
    DANGEROUS = "DANGEROUS"

class ComplianceStatus(Enum):
    """Compliance status enumeration"""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"

@dataclass
class NetworkInfo:
    """Network information model"""
    ssid: str
    bssid: str
    channel: int
    frequency: float
    signal_strength: int  # dBm
    encryption_type: str
    cipher: Optional[str] = None
    authentication: Optional[str] = None
    vendor: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'frequency': self.frequency,
            'signal_strength': self.signal_strength,
            'encryption_type': self.encryption_type,
            'cipher': self.cipher,
            'authentication': self.authentication,
            'vendor': self.vendor
        }

@dataclass
class Vulnerability:
    """Vulnerability model"""
    id: str
    name: str
    severity: str  # Critical, High, Medium, Low
    cve: Optional[str] = None
    description: str = ""
    affected_components: List[str] = field(default_factory=list)
    remediation: str = ""
    cvss_score: Optional[float] = None
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'severity': self.severity,
            'cve': self.cve,
            'description': self.description,
            'affected_components': self.affected_components,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score
        }

@dataclass
class ThreatIndicator:
    """Threat indicator model"""
    threat_type: str
    confidence: float  # 0.0 to 1.0
    description: str
    indicators: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'threat_type': self.threat_type,
            'confidence': self.confidence,
            'description': self.description,
            'indicators': self.indicators,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class ComplianceCheck:
    """Compliance check result model"""
    standard: str  # PCI-DSS, HIPAA, ISO27001
    requirement_id: str
    requirement_name: str
    status: ComplianceStatus
    details: str = ""
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'standard': self.standard,
            'requirement_id': self.requirement_id,
            'requirement_name': self.requirement_name,
            'status': self.status.value,
            'details': self.details,
            'evidence': self.evidence
        }

@dataclass
class SecurityMetrics:
    """Security metrics model"""
    encryption_score: float  # 0-100
    signal_quality_score: float  # 0-100
    vulnerability_score: float  # 0-100
    compliance_score: float  # 0-100
    threat_score: float  # 0-100
    overall_risk_score: float  # 0-100
    
    def to_dict(self) -> Dict:
        return {
            'encryption_score': self.encryption_score,
            'signal_quality_score': self.signal_quality_score,
            'vulnerability_score': self.vulnerability_score,
            'compliance_score': self.compliance_score,
            'threat_score': self.threat_score,
            'overall_risk_score': self.overall_risk_score
        }

@dataclass
class ScanResult:
    """Complete scan result model"""
    scan_id: str
    timestamp: datetime
    network_info: NetworkInfo
    risk_level: RiskLevel
    security_metrics: SecurityMetrics
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    threats: List[ThreatIndicator] = field(default_factory=list)
    compliance_checks: List[ComplianceCheck] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat(),
            'network_info': self.network_info.to_dict(),
            'risk_level': self.risk_level.value,
            'security_metrics': self.security_metrics.to_dict(),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'threats': [t.to_dict() for t in self.threats],
            'compliance_checks': [c.to_dict() for c in self.compliance_checks],
            'recommendations': self.recommendations
        }

@dataclass
class ReportMetadata:
    """Report metadata model"""
    report_id: str
    generated_at: datetime
    scan_id: str
    analyst_name: Optional[str] = None
    organization: Optional[str] = None
    report_type: str = "Comprehensive Security Analysis"
    
    def to_dict(self) -> Dict:
        return {
            'report_id': self.report_id,
            'generated_at': self.generated_at.isoformat(),
            'scan_id': self.scan_id,
            'analyst_name': self.analyst_name,
            'organization': self.organization,
            'report_type': self.report_type
        }
