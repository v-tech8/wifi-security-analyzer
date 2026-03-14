"""
AI Advisor Module — Google Gemini AI Integration
Provides intelligent WiFi security suggestions and recommendations
"""

import config

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class AIAdvisor:
    """AI-powered security advisor using Google Gemini"""

    def __init__(self):
        self.model = None
        self._init_gemini()

    def _init_gemini(self):
        """Initialize Google Gemini client"""
        if not GEMINI_AVAILABLE:
            return
        api_key = getattr(config, 'GEMINI_API_KEY', '')
        if api_key and api_key.strip():
            try:
                genai.configure(api_key=api_key.strip())
                self.model = genai.GenerativeModel('gemini-1.5-flash')
            except Exception:
                self.model = None

    def get_ai_suggestions(self, scan_data: dict) -> dict:
        """
        Generate AI-powered security suggestions based on scan results.
        Falls back to enhanced rule-based suggestions if Gemini is unavailable.

        Args:
            scan_data: dict with keys like risk_level, security_metrics,
                       vulnerabilities, threats, compliance_checks, network_info

        Returns:
            dict with 'suggestions' (list[str]), 'summary' (str), 'source' (str)
        """
        if self.model:
            try:
                return self._gemini_suggestions(scan_data)
            except Exception as e:
                # Fallback gracefully
                return self._rule_based_suggestions(scan_data, error=str(e))
        else:
            return self._rule_based_suggestions(scan_data)

    # ------------------------------------------------------------------ #
    # Gemini path
    # ------------------------------------------------------------------ #

    def _gemini_suggestions(self, scan_data: dict) -> dict:
        """Call Gemini API and return structured suggestions"""
        prompt = self._build_prompt(scan_data)
        response = self.model.generate_content(prompt)
        text = response.text.strip()

        # Parse numbered list into individual items
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        suggestions = []
        summary_lines = []
        in_list = False

        for line in lines:
            if line[0].isdigit() and ('.' in line[:3] or ')' in line[:3]):
                in_list = True
                suggestion = line.split('.', 1)[-1].split(')', 1)[-1].strip()
                if suggestion:
                    suggestions.append(suggestion)
            elif not in_list:
                summary_lines.append(line)

        if not suggestions:
            # If model didn't use numbered list just return paragraphs
            suggestions = [l for l in lines if len(l) > 30]

        summary = ' '.join(summary_lines).strip() or "AI analysis complete."

        return {
            'suggestions': suggestions[:8],   # cap at 8
            'summary': summary[:500],
            'source': 'gemini'
        }

    def _build_prompt(self, scan_data: dict) -> str:
        """Build a detailed security analysis prompt for Gemini"""
        risk_level  = scan_data.get('risk_level', 'UNKNOWN')
        metrics     = scan_data.get('security_metrics', {})
        network     = scan_data.get('network_info', {})
        vulns       = scan_data.get('vulnerabilities', [])
        threats     = scan_data.get('threats', [])
        compliance  = scan_data.get('compliance_checks', [])

        enc_score   = metrics.get('encryption_score', 'N/A')
        signal_score= metrics.get('signal_quality_score', 'N/A')
        vuln_score  = metrics.get('vulnerability_score', 'N/A')
        comp_score  = metrics.get('compliance_score', 'N/A')
        risk_score  = metrics.get('overall_risk_score', 'N/A')

        ssid        = network.get('ssid', 'Unknown')
        enc_type    = network.get('encryption_type', 'Unknown')
        signal      = network.get('signal_strength', 'N/A')
        cipher      = network.get('cipher', 'N/A')

        vuln_names  = ', '.join(v.get('name', '?') for v in vulns) or 'None'
        threat_types= ', '.join(t.get('threat_type', '?') for t in threats) or 'None'
        non_comp    = [c for c in compliance if c.get('status') == 'non_compliant']
        nc_list     = ', '.join(f"{c.get('standard','?')} {c.get('requirement_id','')}" for c in non_comp) or 'None'

        prompt = f"""You are an expert cybersecurity analyst specializing in Wi-Fi network security.
A user has just scanned their Wi-Fi network and received these results.
Analyze the data and provide exactly 5 to 7 practical, prioritized security recommendations.

=== SCAN RESULTS ===
Network SSID        : {ssid}
Encryption Type     : {enc_type}
Cipher Suite        : {cipher}
Signal Strength     : {signal} dBm
Overall Risk Level  : {risk_level}
Overall Risk Score  : {risk_score}/100

Security Metrics (0-100, higher is better):
  - Encryption Score     : {enc_score}
  - Signal Quality Score : {signal_score}
  - Vulnerability Score  : {vuln_score}
  - Compliance Score     : {comp_score}

Detected Vulnerabilities : {vuln_names}
Detected Threats         : {threat_types}
Non-Compliant Standards  : {nc_list}

=== INSTRUCTIONS ===
1. Write a one-sentence executive summary first.
2. Then provide a numbered list of 5-7 specific, actionable security recommendations.
3. Order them by priority (highest risk first).
4. Keep each recommendation concise (1-2 sentences max).
5. Use plain English — no markdown headers, no asterisks, no bold marks.
6. Focus on PRACTICAL steps the user can take immediately.
"""
        return prompt

    # ------------------------------------------------------------------ #
    # Rule-based fallback
    # ------------------------------------------------------------------ #

    def _rule_based_suggestions(self, scan_data: dict, error: str = '') -> dict:
        """Enhanced rule-based fallback when Gemini is unavailable"""
        metrics    = scan_data.get('security_metrics', {})
        network    = scan_data.get('network_info', {})
        vulns      = scan_data.get('vulnerabilities', [])
        threats    = scan_data.get('threats', [])
        risk_level = scan_data.get('risk_level', 'UNKNOWN')

        enc_type   = network.get('encryption_type', 'Unknown')
        signal     = network.get('signal_strength', -100)
        enc_score  = metrics.get('encryption_score', 50)
        comp_score = metrics.get('compliance_score', 50)

        suggestions = []

        # Encryption advice
        if enc_type in ['Open', 'WEP']:
            suggestions.append(
                "CRITICAL: Your network uses no or extremely weak encryption. "
                "Log into your router admin panel and switch to WPA3 or WPA2-AES immediately."
            )
        elif enc_type == 'WPA':
            suggestions.append(
                "Your network uses WPA which is outdated and vulnerable. "
                "Upgrade to WPA3 or at minimum WPA2-AES in your router settings."
            )
        elif enc_type == 'WPA2-TKIP':
            suggestions.append(
                "Upgrade your encryption cipher from TKIP to AES. "
                "TKIP has known weaknesses — find this setting under your router's wireless security options."
            )

        # Signal advice
        if isinstance(signal, (int, float)) and signal < -70:
            suggestions.append(
                "Your signal strength is poor. Consider repositioning your router or "
                "adding a Wi-Fi extender to reduce interference and potential man-in-the-middle attack surface."
            )

        # Threats
        for threat in threats:
            t_type = threat.get('threat_type', '')
            if t_type == 'evil_twin':
                suggestions.append(
                    "Possible Evil Twin attack detected! Verify your network's BSSID (router MAC address) "
                    "matches what your router shows in its admin panel."
                )
            elif t_type == 'deauth_attack':
                suggestions.append(
                    "Abnormal packet patterns detected. Enable Protected Management Frames (PMF/802.11w) "
                    "in your router settings to defend against deauthentication attacks."
                )

        # Vulnerability advice
        for vuln in vulns:
            vuln_id = vuln.get('id', '')
            if vuln_id == 'KRACK':
                suggestions.append(
                    "KRACK vulnerability detected. Update your router firmware and all "
                    "client devices (phones, laptops) to their latest software versions immediately."
                )
            elif vuln_id == 'FragAttacks':
                suggestions.append(
                    "FragAttacks vulnerability detected. Apply the latest vendor security patches "
                    "and disable frame aggregation in router advanced settings if the option exists."
                )

        # Compliance
        if comp_score < 50:
            suggestions.append(
                "Compliance failures detected. Review PCI-DSS / HIPAA / ISO27001 requirements "
                "and ensure your network uses WPA2-AES or WPA3 with strong access controls."
            )

        # General best practices
        suggestions.extend([
            "Use a strong, unique Wi-Fi password (minimum 16 characters mixing letters, numbers, and symbols).",
            "Enable automatic firmware updates on your router to stay protected against new vulnerabilities.",
            "Create a separate guest network for IoT devices and visitors to isolate them from your main network.",
        ])

        summary = (
            f"Your network is rated {risk_level}. "
            "Review the following recommendations to improve your security posture."
        )
        if error:
            summary = "[Gemini AI unavailable — showing rule-based advice] " + summary

        return {
            'suggestions': suggestions[:7],
            'summary': summary,
            'source': 'rule_based'
        }
