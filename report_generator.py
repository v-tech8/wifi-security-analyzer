"""
Professional PDF Report Generator for Wi-Fi Security Analysis
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    PageBreak, Image as RLImage, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import io
from datetime import datetime
from typing import Dict, List
import config
from models import ScanResult, RiskLevel, ComplianceStatus

class ReportGenerator:
    """Generate professional PDF security reports"""
    
    def __init__(self):
        self.config = config.REPORT_CONFIG
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor(self.config['colors']['primary']),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName=self.config['fonts']['title']
        ))
        
        # Section heading
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor(self.config['colors']['secondary']),
            spaceAfter=12,
            spaceBefore=12,
            fontName=self.config['fonts']['heading']
        ))
        
        # Risk badge style
        self.styles.add(ParagraphStyle(
            name='RiskBadge',
            parent=self.styles['Normal'],
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20
        ))
    
    def generate_report(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Generate comprehensive PDF report
        
        Args:
            scan_result: ScanResult object with analysis data
            output_path: Path to save PDF file
            
        Returns:
            bool: Success status
        """
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=self.config['margins']['right'],
                leftMargin=self.config['margins']['left'],
                topMargin=self.config['margins']['top'],
                bottomMargin=self.config['margins']['bottom']
            )
            
            # Build content
            story = []
            
            # Cover page
            story.extend(self._create_cover_page(scan_result))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(scan_result))
            story.append(PageBreak())
            
            # Network details
            story.extend(self._create_network_details(scan_result))
            story.append(Spacer(1, 0.3*inch))
            
            # Security metrics
            story.extend(self._create_security_metrics(scan_result))
            story.append(PageBreak())
            
            # Vulnerabilities
            if scan_result.vulnerabilities:
                story.extend(self._create_vulnerabilities_section(scan_result))
                story.append(PageBreak())
            
            # Threats
            if scan_result.threats:
                story.extend(self._create_threats_section(scan_result))
                story.append(PageBreak())
            
            # Compliance
            story.extend(self._create_compliance_section(scan_result))
            story.append(PageBreak())
            
            # Recommendations
            story.extend(self._create_recommendations_section(scan_result))
            
            # Build PDF
            doc.build(story, onFirstPage=self._add_footer, onLaterPages=self._add_footer)
            
            return True
            
        except Exception as e:
            print(f"Error generating report: {e}")
            return False
    
    def _create_cover_page(self, scan_result: ScanResult) -> List:
        """Create report cover page"""
        elements = []
        
        # Title
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(
            self.config['title'],
            self.styles['CustomTitle']
        ))
        
        elements.append(Spacer(1, 0.5*inch))
        
        # Risk level badge
        risk_color = self._get_risk_color(scan_result.risk_level)
        risk_text = f'<font color="{risk_color}"><b>{scan_result.risk_level.value}</b></font>'
        elements.append(Paragraph(risk_text, self.styles['RiskBadge']))
        
        # Network name
        elements.append(Paragraph(
            f'<b>Network:</b> {scan_result.network_info.ssid}',
            self.styles['Normal']
        ))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Metadata table
        metadata = [
            ['Report ID:', scan_result.scan_id[:8]],
            ['Generated:', scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')],
            ['BSSID:', scan_result.network_info.bssid],
            ['Overall Risk Score:', f'{scan_result.security_metrics.overall_risk_score:.1f}/100']
        ]
        
        table = Table(metadata, colWidths=[2*inch, 3*inch])
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), self.config['fonts']['heading']),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(table)
        
        return elements
    
    def _create_executive_summary(self, scan_result: ScanResult) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph('Executive Summary', self.styles['SectionHeading']))
        
        # Summary text
        summary_text = f"""
        This report presents a comprehensive security analysis of the Wi-Fi network 
        <b>{scan_result.network_info.ssid}</b>. The analysis was conducted on 
        {scan_result.timestamp.strftime('%B %d, %Y at %H:%M')}.
        <br/><br/>
        <b>Key Findings:</b><br/>
        • Overall Risk Level: <font color="{self._get_risk_color(scan_result.risk_level)}"><b>{scan_result.risk_level.value}</b></font><br/>
        • Encryption: {scan_result.network_info.encryption_type}<br/>
        • Vulnerabilities Detected: {len(scan_result.vulnerabilities)}<br/>
        • Threats Identified: {len(scan_result.threats)}<br/>
        • Compliance Score: {scan_result.security_metrics.compliance_score:.1f}%
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Add risk score chart
        chart_img = self._create_risk_score_chart(scan_result.security_metrics)
        if chart_img:
            elements.append(chart_img)
        
        return elements
    
    def _create_network_details(self, scan_result: ScanResult) -> List:
        """Create network details section"""
        elements = []
        
        elements.append(Paragraph('Network Details', self.styles['SectionHeading']))
        
        network = scan_result.network_info
        
        details = [
            ['Parameter', 'Value'],
            ['SSID', network.ssid],
            ['BSSID (MAC Address)', network.bssid],
            ['Channel', str(network.channel)],
            ['Frequency', f'{network.frequency:.3f} GHz'],
            ['Signal Strength', f'{network.signal_strength} dBm'],
            ['Encryption Type', network.encryption_type],
            ['Cipher Suite', network.cipher or 'N/A'],
            ['Authentication', network.authentication or 'N/A'],
            ['Vendor', network.vendor or 'Unknown']
        ]
        
        table = Table(details, colWidths=[2.5*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.config['colors']['primary'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), self.config['fonts']['heading']),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor(self.config['colors']['light_bg'])])
        ]))
        
        elements.append(table)
        
        return elements
    
    def _create_security_metrics(self, scan_result: ScanResult) -> List:
        """Create security metrics section"""
        elements = []
        
        elements.append(Paragraph('Security Metrics', self.styles['SectionHeading']))
        
        metrics = scan_result.security_metrics
        
        metrics_data = [
            ['Metric', 'Score', 'Rating'],
            ['Encryption Strength', f'{metrics.encryption_score:.1f}/100', self._get_rating(metrics.encryption_score)],
            ['Signal Quality', f'{metrics.signal_quality_score:.1f}/100', self._get_rating(metrics.signal_quality_score)],
            ['Vulnerability Assessment', f'{metrics.vulnerability_score:.1f}/100', self._get_rating(metrics.vulnerability_score)],
            ['Compliance Status', f'{metrics.compliance_score:.1f}/100', self._get_rating(metrics.compliance_score)],
            ['Threat Level', f'{metrics.threat_score:.1f}/100', self._get_rating(metrics.threat_score)],
            ['', '', ''],
            ['Overall Risk Score', f'{metrics.overall_risk_score:.1f}/100', self._get_rating(metrics.overall_risk_score)]
        ]
        
        table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.config['colors']['secondary'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), self.config['fonts']['heading']),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -2), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor(self.config['colors']['light_bg'])]),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor(self.config['colors']['primary'])),
            ('TEXTCOLOR', (0, -1), (-1, -1), colors.whitesmoke),
            ('FONTNAME', (0, -1), (-1, -1), self.config['fonts']['heading']),
            ('FONTSIZE', (0, -1), (-1, -1), 12),
            ('SPAN', (0, -2), (-1, -2)),
        ]))
        
        elements.append(table)
        
        return elements
    
    def _create_vulnerabilities_section(self, scan_result: ScanResult) -> List:
        """Create vulnerabilities section"""
        elements = []
        
        elements.append(Paragraph('Vulnerabilities Detected', self.styles['SectionHeading']))
        
        if not scan_result.vulnerabilities:
            elements.append(Paragraph(
                '<font color="green">✓ No vulnerabilities detected</font>',
                self.styles['Normal']
            ))
            return elements
        
        for vuln in scan_result.vulnerabilities:
            severity_color = self._get_severity_color(vuln.severity)
            
            vuln_text = f"""
            <b><font color="{severity_color}">{vuln.severity.upper()}</font>: {vuln.name}</b><br/>
            <b>ID:</b> {vuln.id} {f'({vuln.cve})' if vuln.cve else ''}<br/>
            <b>CVSS Score:</b> {vuln.cvss_score if vuln.cvss_score else 'N/A'}<br/>
            <b>Description:</b> {vuln.description}<br/>
            <b>Affected Components:</b> {', '.join(vuln.affected_components)}<br/>
            <b>Remediation:</b> {vuln.remediation}
            """
            
            elements.append(KeepTogether([
                Paragraph(vuln_text, self.styles['Normal']),
                Spacer(1, 0.2*inch)
            ]))
        
        return elements
    
    def _create_threats_section(self, scan_result: ScanResult) -> List:
        """Create threats section"""
        elements = []
        
        elements.append(Paragraph('Threat Analysis', self.styles['SectionHeading']))
        
        if not scan_result.threats:
            elements.append(Paragraph(
                '<font color="green">✓ No active threats detected</font>',
                self.styles['Normal']
            ))
            return elements
        
        for threat in scan_result.threats:
            confidence_pct = threat.confidence * 100
            confidence_color = self._get_confidence_color(threat.confidence)
            
            threat_text = f"""
            <b>{threat.threat_type.upper().replace('_', ' ')}</b><br/>
            <b>Confidence:</b> <font color="{confidence_color}">{confidence_pct:.0f}%</font><br/>
            <b>Description:</b> {threat.description}<br/>
            <b>Indicators:</b> {', '.join(threat.indicators)}<br/>
            <b>Detected:</b> {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            elements.append(KeepTogether([
                Paragraph(threat_text, self.styles['Normal']),
                Spacer(1, 0.2*inch)
            ]))
        
        return elements
    
    def _create_compliance_section(self, scan_result: ScanResult) -> List:
        """Create compliance section"""
        elements = []
        
        elements.append(Paragraph('Compliance Assessment', self.styles['SectionHeading']))
        
        # Group by standard
        standards = {}
        for check in scan_result.compliance_checks:
            if check.standard not in standards:
                standards[check.standard] = []
            standards[check.standard].append(check)
        
        for standard_name, checks in standards.items():
            elements.append(Paragraph(f'<b>{standard_name}</b>', self.styles['Heading3']))
            
            compliance_data = [['Requirement', 'Status', 'Details']]
            
            for check in checks:
                status_symbol = self._get_compliance_symbol(check.status)
                compliance_data.append([
                    f'{check.requirement_id}: {check.requirement_name}',
                    status_symbol,
                    check.details
                ])
            
            table = Table(compliance_data, colWidths=[2.5*inch, 1*inch, 2.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.config['colors']['secondary'])),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), self.config['fonts']['heading']),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor(self.config['colors']['light_bg'])]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            elements.append(table)
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_recommendations_section(self, scan_result: ScanResult) -> List:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph('Recommendations', self.styles['SectionHeading']))
        
        elements.append(Paragraph(
            'Based on the security analysis, we recommend the following actions:',
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        for i, rec in enumerate(scan_result.recommendations, 1):
            elements.append(Paragraph(f'{i}. {rec}', self.styles['Normal']))
            elements.append(Spacer(1, 0.05*inch))
        
        return elements
    
    def _create_risk_score_chart(self, metrics) -> RLImage:
        """Create risk score bar chart"""
        try:
            fig, ax = plt.subplots(figsize=(8, 4))
            
            categories = ['Encryption', 'Signal', 'Vulnerabilities', 'Compliance', 'Threats']
            scores = [
                metrics.encryption_score,
                metrics.signal_quality_score,
                metrics.vulnerability_score,
                metrics.compliance_score,
                metrics.threat_score
            ]
            
            colors_list = [self._get_bar_color(score) for score in scores]
            
            ax.barh(categories, scores, color=colors_list)
            ax.set_xlabel('Score (0-100)')
            ax.set_title('Security Metrics Breakdown')
            ax.set_xlim(0, 100)
            
            # Add score labels
            for i, score in enumerate(scores):
                ax.text(score + 2, i, f'{score:.1f}', va='center')
            
            plt.tight_layout()
            
            # Convert to image
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
            img_buffer.seek(0)
            plt.close()
            
            return RLImage(img_buffer, width=5*inch, height=2.5*inch)
            
        except Exception as e:
            print(f"Error creating chart: {e}")
            return None
    
    def _add_footer(self, canvas_obj, doc):
        """Add footer to pages"""
        canvas_obj.saveState()
        canvas_obj.setFont(self.config['fonts']['body'], 9)
        canvas_obj.setFillColor(colors.grey)
        canvas_obj.drawString(
            inch,
            0.5*inch,
            config.REPORT_FOOTER
        )
        canvas_obj.drawRightString(
            A4[0] - inch,
            0.5*inch,
            f"Page {doc.page}"
        )
        canvas_obj.restoreState()
    
    def _get_risk_color(self, risk_level: RiskLevel) -> str:
        """Get color for risk level"""
        colors_map = {
            RiskLevel.SAFE: self.config['colors']['success'],
            RiskLevel.MEDIUM: self.config['colors']['warning'],
            RiskLevel.DANGEROUS: self.config['colors']['danger']
        }
        return colors_map.get(risk_level, '#000000')
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for vulnerability severity"""
        colors_map = {
            'Critical': self.config['colors']['danger'],
            'High': '#ff6f00',
            'Medium': self.config['colors']['warning'],
            'Low': '#fbc02d'
        }
        return colors_map.get(severity, '#000000')
    
    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for threat confidence"""
        if confidence >= 0.7:
            return self.config['colors']['danger']
        elif confidence >= 0.4:
            return self.config['colors']['warning']
        else:
            return '#fbc02d'
    
    def _get_bar_color(self, score: float) -> str:
        """Get color for bar chart based on score"""
        if score >= 70:
            return '#4caf50'  # Green
        elif score >= 40:
            return '#ff9800'  # Orange
        else:
            return '#f44336'  # Red
    
    def _get_rating(self, score: float) -> str:
        """Get text rating from score"""
        if score >= 80:
            return 'Excellent'
        elif score >= 60:
            return 'Good'
        elif score >= 40:
            return 'Fair'
        else:
            return 'Poor'
    
    def _get_compliance_symbol(self, status: ComplianceStatus) -> str:
        """Get symbol for compliance status"""
        symbols = {
            ComplianceStatus.COMPLIANT: '✓ Compliant',
            ComplianceStatus.PARTIAL: '⚠ Partial',
            ComplianceStatus.NON_COMPLIANT: '✗ Non-Compliant',
            ComplianceStatus.NOT_APPLICABLE: '- N/A'
        }
        return symbols.get(status, '?')
