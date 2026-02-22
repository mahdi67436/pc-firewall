"""
Firewall Audit System
PC-Omnifix - Comprehensive firewall auditing and security checks

Provides:
- Firewall status verification
- Insecure rule detection
- Disabled firewall detection
- Security recommendations

Author: PC-Omnifix
Version: 1.0.0
"""

import logging
import json
import os
import datetime
from typing import Dict, List, Tuple, Optional
from .firewall_manager import FirewallManager

logger = logging.getLogger(__name__)


class FirewallAuditor:
    """
    Firewall Security Auditor
    
    Performs comprehensive audits of Windows Firewall configuration
    and provides security recommendations.
    """
    
    # Known insecure ports
    DANGEROUS_PORTS = {
        23: 'Telnet (unencrypted)',
        135: 'RPC (remote exploit)',
        139: 'NetBIOS (information disclosure)',
        445: 'SMB (remote exploit)',
        1433: 'MSSQL',
        1434: 'MSSQL Browser',
        3306: 'MySQL',
        3389: 'RDP (remote desktop)',
        4444: 'Metasploit default',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt',
        27017: 'MongoDB'
    }
    
    # Critical system services that should be protected
    CRITICAL_SERVICES = [
        'svchost.exe',
        'lsass.exe',
        'services.exe',
        'wininit.exe',
        'csrss.exe',
        'smss.exe',
        'winlogon.exe',
        'explorer.exe'
    ]
    
    def __init__(self):
        """Initialize auditor"""
        self.firewall = FirewallManager()
        self.audit_report = {}
        
    def run_full_audit(self) -> Dict:
        """
        Run a complete firewall security audit
        
        Returns:
            Dictionary containing all audit results
        """
        audit = {
            'timestamp': datetime.datetime.now().isoformat(),
            'firewall_status': self.check_firewall_status(),
            'insecure_rules': self.detect_insecure_rules(),
            'disabled_profiles': self.detect_disabled_profiles(),
            'suspicious_rules': self.detect_suspicious_rules(),
            'recommendations': [],
            'overall_score': 0
        }
        
        # Generate recommendations
        audit['recommendations'] = self._generate_recommendations(audit)
        
        # Calculate overall security score (0-100)
        audit['overall_score'] = self._calculate_score(audit)
        
        self.audit_report = audit
        return audit
        
    def check_firewall_status(self) -> Dict:
        """
        Check if firewall is enabled on all profiles
        
        Returns:
            Status dictionary
        """
        status = self.firewall.get_firewall_status()
        
        result = {
            'domain_enabled': status['domain']['enabled'],
            'private_enabled': status['private']['enabled'],
            'public_enabled': status['public']['enabled'],
            'overall': status['overall'],
            'secure': all([
                status['domain']['enabled'],
                status['private']['enabled'],
                status['public']['enabled']
            ])
        }
        
        return result
        
    def detect_disabled_profiles(self) -> List[Dict]:
        """
        Detect any disabled firewall profiles
        
        Returns:
            List of disabled profiles
        """
        disabled = []
        status = self.firewall.get_firewall_status()
        
        for profile in ['domain', 'private', 'public']:
            if not status[profile]['enabled']:
                disabled.append({
                    'profile': profile,
                    'risk': 'high' if profile == 'public' else 'medium',
                    'message': f'{profile.capitalize()} profile is disabled'
                })
                
        return disabled
        
    def detect_insecure_rules(self) -> List[Dict]:
        """
        Detect rules that may pose security risks
        
        Returns:
            List of potentially insecure rules
        """
        insecure = []
        
        try:
            rules = self.firewall.get_rules()
            
            for rule in rules:
                # Check for dangerous ports
                # Note: This is a basic check, real implementation would need
                # to parse the rule details more thoroughly
                
                # Check for overly permissive rules
                if rule.get('Enabled') == 'True':
                    action = rule.get('Action', '')
                    direction = rule.get('Direction', '')
                    
                    # Allow all inbound is suspicious
                    if (action == 'Allow' and direction == 'Inbound' and 
                        rule.get('Profile') == 'Any'):
                        insecure.append({
                            'rule': rule.get('DisplayName', 'Unknown'),
                            'risk': 'medium',
                            'issue': 'Allows all inbound traffic from any profile'
                        })
                        
        except Exception as e:
            logger.error(f"Error detecting insecure rules: {e}")
            
        return insecure
        
    def detect_suspicious_rules(self) -> List[Dict]:
        """
        Detect suspicious or potentially malicious rules
        
        Returns:
            List of suspicious rules
        """
        suspicious = []
        
        try:
            rules = self.firewall.get_rules()
            
            for rule in rules:
                display_name = rule.get('DisplayName', '')
                
                # Check for rules that might be from malware
                suspicious_patterns = [
                    'meterpreter',
                    'payload',
                    'reverse_shell',
                    'backdoor',
                    'rootkit'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern.lower() in display_name.lower():
                        suspicious.append({
                            'rule': display_name,
                            'risk': 'high',
                            'issue': f'Potentially malicious rule detected: {pattern}'
                        })
                        
        except Exception as e:
            logger.error(f"Error detecting suspicious rules: {e}")
            
        return suspicious
        
    def check_listening_services(self) -> List[Dict]:
        """
        Check for services listening on network ports
        
        Returns:
            List of listening services
        """
        listening = []
        
        try:
            import subprocess
            
            # Get listening ports
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', 
                 'Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    connections = data if isinstance(data, list) else [data]
                    
                    for conn in connections:
                        port = conn.get('LocalPort', 0)
                        address = conn.get('LocalAddress', '')
                        
                        # Check if port is dangerous
                        warning = None
                        if port in self.DANGEROUS_PORTS:
                            warning = self.DANGEROUS_PORTS[port]
                            
                        listening.append({
                            'port': port,
                            'address': address,
                            'risk': 'high' if warning else 'low',
                            'warning': warning
                        })
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.error(f"Error checking listening services: {e}")
            
        return listening
        
    def export_audit_report(self, filepath: str = None) -> Tuple[bool, str]:
        """
        Export audit report to file
        
        Args:
            filepath: Optional custom filepath
            
        Returns:
            Tuple of (success, filepath)
        """
        if not self.audit_report:
            self.run_full_audit()
            
        try:
            if not filepath:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                filepath = os.path.join(
                    self.firewall.backup_dir,
                    f'firewall_audit_{timestamp}.json'
                )
                
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.audit_report, f, indent=2)
                
            logger.info(f"Audit report exported to {filepath}")
            return True, filepath
            
        except Exception as e:
            logger.error(f"Failed to export audit report: {e}")
            return False, str(e)
            
    def _generate_recommendations(self, audit: Dict) -> List[str]:
        """Generate security recommendations based on audit results"""
        recommendations = []
        
        # Check firewall status
        if not audit['firewall_status']['secure']:
            recommendations.append(
                "⚠️ Enable Windows Firewall on all profiles for complete protection"
            )
            
        # Check disabled profiles
        for disabled in audit['disabled_profiles']:
            if disabled['risk'] == 'high':
                recommendations.append(
                    f"🔴 CRITICAL: {disabled['message']} - This significantly increases security risk"
                )
                
        # Check insecure rules
        if audit['insecure_rules']:
            recommendations.append(
                f"⚡ Review {len(audit['insecure_rules'])} overly permissive firewall rules"
            )
            
        # Check suspicious rules
        if audit['suspicious_rules']:
            recommendations.append(
                f"🚨 Investigate {len(audit['suspicious_rules'])} suspicious firewall rules"
            )
            
        # General recommendations
        if audit['firewall_status']['secure']:
            recommendations.append(
                "✅ Firewall is properly configured on all profiles"
            )
            
        return recommendations
        
    def _calculate_score(self, audit: Dict) -> int:
        """Calculate overall security score (0-100)"""
        score = 100
        
        # Deduct for disabled profiles
        score -= len(audit['disabled_profiles']) * 20
        
        # Deduct for insecure rules
        score -= len(audit['insecure_rules']) * 5
        
        # Deduct for suspicious rules
        score -= len(audit['suspicious_rules']) * 15
        
        # Ensure score is within bounds
        return max(0, min(100, score))
        
    def print_audit_summary(self):
        """Print a formatted audit summary to console"""
        if not self.audit_report:
            self.run_full_audit()
            
        audit = self.audit_report
        
        print("\n" + "="*60)
        print("       FIREWALL SECURITY AUDIT REPORT")
        print("="*60)
        print(f"\n📅 Date: {audit['timestamp']}")
        print(f"\n🛡️  Overall Security Score: {audit['overall_score']}/100")
        
        print("\n--- Firewall Status ---")
        status = audit['firewall_status']
        print(f"  Domain:  {'✓ Enabled' if status['domain_enabled'] else '✗ Disabled'}")
        print(f"  Private: {'✓ Enabled' if status['private_enabled'] else '✗ Disabled'}")
        print(f"  Public:  {'✓ Enabled' if status['public_enabled'] else '✗ Disabled'}")
        
        if audit['disabled_profiles']:
            print("\n⚠️  Disabled Profiles:")
            for p in audit['disabled_profiles']:
                print(f"    - {p['profile'].capitalize()}: {p['message']}")
                
        if audit['insecure_rules']:
            print(f"\n⚡ Insecure Rules: {len(audit['insecure_rules'])}")
            for rule in audit['insecure_rules'][:5]:
                print(f"    - {rule['rule'][:50]}")
                
        if audit['suspicious_rules']:
            print(f"\n🚨 Suspicious Rules: {len(audit['suspicious_rules'])}")
            for rule in audit['suspicious_rules']:
                print(f"    - {rule['rule'][:50]}")
                
        print("\n--- Recommendations ---")
        for rec in audit['recommendations']:
            print(f"  {rec}")
            
        print("\n" + "="*60 + "\n")


# Singleton instance
_auditor = None

def get_auditor() -> FirewallAuditor:
    """Get singleton auditor instance"""
    global _auditor
    if _auditor is None:
        _auditor = FirewallAuditor()
    return _auditor
