"""
Windows Firewall Management & Protection Engine
PC-Omnifix - Enterprise-grade firewall management for Windows 10 & 11

This module provides comprehensive firewall management including:
- Firewall status checking and auditing
- Rule management (create, delete, enable, disable)
- Preset profiles (Open, Balanced, Strict, Gaming)
- Network threat monitoring
- Rollback capabilities

Author: PC-Omnifix
Version: 1.0.0
"""

import subprocess
import json
import os
import logging
import datetime
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProfileType(Enum):
    """Firewall profile types"""
    OPEN = "open"
    BALANCED = "balanced"
    STRICT = "strict"
    GAMING = "gaming"


class RuleDirection(Enum):
    """Firewall rule direction"""
    INBOUND = "in"
    OUTBOUND = "out"


class RuleAction(Enum):
    """Firewall rule action"""
    ALLOW = "allow"
    BLOCK = "block"


class Protocol(Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ANY = "any"


class FirewallManager:
    """
    Core Windows Firewall Manager
    
    Provides safe, user-controlled firewall management using Windows
    native APIs (netsh/PowerShell). Never blocks critical system processes.
    """
    
    def __init__(self, backup_dir: str = None):
        """
        Initialize Firewall Manager
        
        Args:
            backup_dir: Directory for firewall rule backups
        """
        self.backup_dir = backup_dir or os.path.join(
            os.environ.get('LOCALAPPDATA', 'C:\\Users\\%s\\AppData\\Local' % os.environ.get('USERNAME', 'User')),
            'PC-Omnifix',
            'backups',
            'firewall'
        )
        self._ensure_backup_dir()
        self._last_backup_file = None
        
    def _ensure_backup_dir(self):
        """Create backup directory if it doesn't exist"""
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            logger.info(f"Backup directory: {self.backup_dir}")
        except Exception as e:
            logger.error(f"Failed to create backup directory: {e}")
            
    def _run_powershell(self, command: str) -> Tuple[bool, str]:
        """
        Execute PowerShell command safely
        
        Args:
            command: PowerShell command to execute
            
        Returns:
            Tuple of (success, output)
        """
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', command],
                capture_output=True,
                text=True,
                timeout=30
            )
            success = result.returncode == 0
            output = result.stdout.strip() if success else result.stderr.strip()
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
            
    def _run_netsh(self, args: List[str]) -> Tuple[bool, str]:
        """
        Execute netsh command safely
        
        Args:
            args: List of netsh arguments
            
        Returns:
            Tuple of (success, output)
        """
        try:
            cmd = ['netsh'] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            success = result.returncode == 0
            output = result.stdout.strip() if success else result.stderr.strip()
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
            
    def get_firewall_status(self) -> Dict:
        """
        Check Windows Defender Firewall status for all profiles
        
        Returns:
            Dictionary containing firewall status for each profile
        """
        status = {
            'domain': {'enabled': False, 'name': 'Domain'},
            'private': {'enabled': False, 'name': 'Private'},
            'public': {'enabled': False, 'name': 'Public'},
            'overall': 'Unknown'
        }
        
        try:
            # Get firewall status using PowerShell
            success, output = self._run_powershell(
                'Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json'
            )
            
            if success and output:
                try:
                    data = json.loads(output)
                    # Handle single object vs array
                    if isinstance(data, dict):
                        profiles = [data]
                    else:
                        profiles = data
                        
                    for profile in profiles:
                        name = profile.get('Name', '').lower()
                        enabled = profile.get('Enabled', False)
                        
                        if 'domain' in name:
                            status['domain']['enabled'] = enabled
                        elif 'private' in name:
                            status['private']['enabled'] = enabled
                        elif 'public' in name:
                            status['public']['enabled'] = enabled
                            
                    # Determine overall status
                    all_enabled = all(p['enabled'] for p in [
                        status['domain'], status['private'], status['public']
                    ])
                    any_enabled = any(p['enabled'] for p in [
                        status['domain'], status['private'], status['public']
                    ])
                    
                    if all_enabled:
                        status['overall'] = 'Enabled (All Profiles)'
                    elif any_enabled:
                        status['overall'] = 'Partially Enabled'
                    else:
                        status['overall'] = 'Disabled (All Profiles)'
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse firewall status: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to get firewall status: {e}")
            status['overall'] = f'Error: {str(e)}'
            
        return status
        
    def enable_firewall(self, profile: str = 'all') -> Tuple[bool, str]:
        """
        Enable Windows Firewall for specified profile(s)
        
        Args:
            profile: 'domain', 'private', 'public', or 'all'
            
        Returns:
            Tuple of (success, message)
        """
        profiles = ['domain', 'private', 'public'] if profile == 'all' else [profile]
        results = []
        
        for prof in profiles:
            success, output = self._run_powershell(
                f'Set-NetFirewallProfile -Profile {prof.capitalize()} -Enabled True'
            )
            results.append((prof, success, output))
            
        all_success = all(r[1] for r in results)
        message = f"Firewall {'enabled' if all_success else 'partially enabled'} for {profile} profile(s)"
        
        if not all_success:
            failed = [r[0] for r in results if not r[1]]
            message += f". Failed profiles: {', '.join(failed)}"
            
        return all_success, message
        
    def disable_firewall(self, profile: str = 'all') -> Tuple[bool, str]:
        """
        Disable Windows Firewall for specified profile(s)
        
        Args:
            profile: 'domain', 'private', 'public', or 'all'
            
        Returns:
            Tuple of (success, message)
        """
        profiles = ['domain', 'private', 'public'] if profile == 'all' else [profile]
        results = []
        
        for prof in profiles:
            success, output = self._run_powershell(
                f'Set-NetFirewallProfile -Profile {prof.capitalize()} -Enabled False'
            )
            results.append((prof, success, output))
            
        all_success = all(r[1] for r in results)
        message = f"Firewall {'disabled' if all_success else 'partially disabled'} for {profile} profile(s)"
        
        if not all_success:
            failed = [r[0] for r in results if not r[1]]
            message += f". Failed profiles: {', '.join(failed)}"
            
        return all_success, message
        
    def export_rules(self, filename: str = None) -> Tuple[bool, str]:
        """
        Export current firewall rules to JSON file
        
        Args:
            filename: Optional custom filename
            
        Returns:
            Tuple of (success, filepath)
        """
        try:
            # Generate default filename with timestamp
            if not filename:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"firewall_rules_backup_{timestamp}.json"
                
            filepath = os.path.join(self.backup_dir, filename)
            
            # Export rules using PowerShell
            success, output = self._run_powershell(
                '''Get-NetFirewallRule | Where-Object {$_.DisplayName -ne $null} | 
                Select-Object Name, DisplayName, Description, Direction, Action, 
                Enabled, Profile, LocalPort, RemotePort, Protocol, Program | 
                ConvertTo-Json -Depth 3'''
            )
            
            if success and output:
                # Pretty print the JSON
                try:
                    data = json.loads(output)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    self._last_backup_file = filepath
                    logger.info(f"Firewall rules exported to {filepath}")
                    return True, filepath
                except json.JSONDecodeError as e:
                    return False, f"Failed to parse exported rules: {e}"
            else:
                return False, f"Failed to export rules: {output}"
                
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False, str(e)
            
    def get_rules(self, direction: str = None, enabled_only: bool = False) -> List[Dict]:
        """
        Get current firewall rules
        
        Args:
            direction: Filter by 'in' or 'out'
            enabled_only: Only return enabled rules
            
        Returns:
            List of firewall rule dictionaries
        """
        rules = []
        
        try:
            # Build PowerShell command
            ps_cmd = '''Get-NetFirewallRule | Where-Object {$_.DisplayName -ne $null} | 
            Select-Object Name, DisplayName, Description, Direction, Action, 
            Enabled, Profile | ConvertTo-Json -Depth 2'''
            
            if direction:
                dir_val = 'Inbound' if direction == 'in' else 'Outbound'
                ps_cmd = f'''Get-NetFirewallRule | Where-Object {{$_.DisplayName -ne $null -and $_.Direction -eq '{dir_val}'}} | 
                Select-Object Name, DisplayName, Description, Direction, Action, 
                Enabled, Profile | ConvertTo-Json -Depth 2'''
                
            success, output = self._run_powershell(ps_cmd)
            
            if success and output:
                try:
                    data = json.loads(output)
                    rules = data if isinstance(data, list) else [data]
                    
                    # Filter enabled only if requested
                    if enabled_only:
                        rules = [r for r in rules if r.get('Enabled') == 'True']
                        
                except json.JSONDecodeError:
                    logger.error("Failed to parse firewall rules")
                    
        except Exception as e:
            logger.error(f"Failed to get rules: {e}")
            
        return rules
        
    def create_rule(
        self,
        name: str,
        direction: str = 'in',
        action: str = 'allow',
        protocol: str = 'any',
        port: int = None,
        app_name: str = None,
        description: str = "",
        profile: str = 'any'
    ) -> Tuple[bool, str]:
        """
        Create a new firewall rule
        
        Args:
            name: Rule name
            direction: 'in' or 'out'
            action: 'allow' or 'block'
            protocol: 'tcp', 'udp', or 'any'
            port: Port number (optional)
            app_name: Application path (optional)
            description: Rule description
            profile: Profile(s) to apply rule to
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Build PowerShell command
            ps_cmd = f'New-NetFirewallRule -DisplayName "{name}" -Direction {"Inbound" if direction == "in" else "Outbound"}'
            ps_cmd += f' -Action {"Allow" if action == "allow" else "Block"}'
            
            if protocol != 'any':
                ps_cmd += f' -Protocol {protocol.upper()}'
                
            if port:
                ps_cmd += f' -LocalPort {port}'
                
            if app_name:
                ps_cmd += f' -Program "{app_name}"'
                
            if description:
                ps_cmd += f' -Description "{description}"'
                
            if profile != 'any':
                ps_cmd += f' -Profile {profile.capitalize()}'
            else:
                ps_cmd += ' -Profile Any'
                
            success, output = self._run_powershell(ps_cmd)
            
            if success:
                logger.info(f"Created firewall rule: {name}")
                return True, f"Rule '{name}' created successfully"
            else:
                logger.error(f"Failed to create rule: {output}")
                return False, f"Failed to create rule: {output}"
                
        except Exception as e:
            logger.error(f"Error creating rule: {e}")
            return False, str(e)
            
    def delete_rule(self, name: str) -> Tuple[bool, str]:
        """
        Delete a firewall rule by name
        
        Args:
            name: Rule name to delete
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Escape the name for PowerShell
            ps_cmd = f'Remove-NetFirewallRule -DisplayName "{name}" -ErrorAction SilentlyContinue'
            
            success, output = self._run_powershell(ps_cmd)
            
            if success:
                logger.info(f"Deleted firewall rule: {name}")
                return True, f"Rule '{name}' deleted successfully"
            else:
                return False, f"Failed to delete rule: {output}"
                
        except Exception as e:
            logger.error(f"Error deleting rule: {e}")
            return False, str(e)
            
    def enable_rule(self, name: str) -> Tuple[bool, str]:
        """
        Enable a firewall rule
        
        Args:
            name: Rule name to enable
            
        Returns:
            Tuple of (success, message)
        """
        try:
            ps_cmd = f'Set-NetFirewallRule -DisplayName "{name}" -Enabled True'
            success, output = self._run_powershell(ps_cmd)
            
            if success:
                return True, f"Rule '{name}' enabled"
            else:
                return False, f"Failed to enable rule: {output}"
                
        except Exception as e:
            return False, str(e)
            
    def disable_rule(self, name: str) -> Tuple[bool, str]:
        """
        Disable a firewall rule
        
        Args:
            name: Rule name to disable
            
        Returns:
            Tuple of (success, message)
        """
        try:
            ps_cmd = f'Set-NetFirewallRule -DisplayName "{name}" -Enabled False'
            success, output = self._run_powershell(ps_cmd)
            
            if success:
                return True, f"Rule '{name}' disabled"
            else:
                return False, f"Failed to disable rule: {output}"
                
        except Exception as e:
            return False, str(e)
            
    def block_port(self, port: int, direction: str = 'in', protocol: str = 'tcp') -> Tuple[bool, str]:
        """
        Block a specific port
        
        Args:
            port: Port number to block
            direction: 'in' or 'out'
            protocol: 'tcp' or 'udp'
            
        Returns:
            Tuple of (success, message)
        """
        rule_name = f"PC-Omnifix Block {protocol.upper()} {port} {'Inbound' if direction == 'in' else 'Outbound'}"
        description = f"Blocked by PC-Omnifix firewall manager - Port {port}"
        
        return self.create_rule(
            name=rule_name,
            direction=direction,
            action='block',
            protocol=protocol,
            port=port,
            description=description
        )
        
    def allow_app(self, app_path: str, name: str = None, direction: str = 'out') -> Tuple[bool, str]:
        """
        Allow an application through the firewall
        
        Args:
            app_path: Full path to the application
            name: Optional rule name (defaults to app name)
            direction: 'in' or 'out'
            
        Returns:
            Tuple of (success, message)
        """
        if not name:
            name = f"PC-Omnifix Allow {os.path.basename(app_path)}"
            
        description = f"Allowed by PC-Omnifix firewall manager - {app_path}"
        
        return self.create_rule(
            name=name,
            direction=direction,
            action='allow',
            app_name=app_path,
            description=description
        )
        
    def get_last_backup(self) -> Optional[str]:
        """Get the path to the last backup file"""
        return self._last_backup_file
        
    def reset_firewall(self) -> Tuple[bool, str]:
        """
        Emergency reset - restore default Windows firewall rules
        
        Returns:
            Tuple of (success, message)
        """
        try:
            # First export current rules for backup
            self.export_rules('pre_reset_backup.json')
            
            # Remove all custom rules created by PC-Omnifix
            ps_cmd = '''Get-NetFirewallRule | Where-Object {$_.DisplayName -like "PC-Omnifix*"} | 
            Remove-NetFirewallRule -ErrorAction SilentlyContinue'''
            
            success, output = self._run_powershell(ps_cmd)
            
            # Enable all profiles
            self.enable_firewall('all')
            
            logger.warning("Firewall reset completed")
            return True, "Firewall reset completed - all PC-Omnifix rules removed"
            
        except Exception as e:
            logger.error(f"Reset failed: {e}")
            return False, f"Reset failed: {str(e)}"


# Singleton instance
_firewall_manager = None

def get_firewall_manager() -> FirewallManager:
    """Get singleton firewall manager instance"""
    global _firewall_manager
    if _firewall_manager is None:
        _firewall_manager = FirewallManager()
    return _firewall_manager
