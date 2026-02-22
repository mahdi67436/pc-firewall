"""
Firewall Profile Manager
PC-Omnifix - Preset firewall profiles for different use cases

Provides preset profiles:
- 🔓 Open (default Windows behavior)
- 🛡 Balanced (recommended)
- 🔒 Strict (maximum protection)
- 🎮 Gaming (low latency, essential ports open)

Author: PC-Omnifix
Version: 1.0.0
"""

import logging
import os
from typing import Dict, List, Tuple, Optional
from .firewall_manager import FirewallManager, ProfileType

logger = logging.getLogger(__name__)


class ProfileManager:
    """
    Manages preset firewall profiles
    
    Profiles are collections of rules and settings optimized for
    different use cases. All profiles are reversible.
    """
    
    # Profile definitions
    PROFILES = {
        ProfileType.OPEN: {
            'name': 'Open',
            'emoji': '🔓',
            'description': 'Default Windows behavior - minimal blocking',
            'firewall_state': 'disabled',
            'rules': [],
            'allow_icmp': True,
            'block_incoming': False
        },
        ProfileType.BALANCED: {
            'name': 'Balanced',
            'emoji': '🛡',
            'description': 'Recommended - blocks unsolicited inbound, allows outbound',
            'firewall_state': 'enabled',
            'rules': [
                # Block common malicious ports
                {'port': 4444, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block Metasploit (4444)'},
                {'port': 31337, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block Back Orifice (31337)'},
                {'port': 12345, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block NetBus (12345)'},
            ],
            'allow_icmp': True,
            'block_incoming': True
        },
        ProfileType.STRICT: {
            'name': 'Strict',
            'emoji': '🔒',
            'description': 'Maximum protection - blocks most inbound, monitors outbound',
            'firewall_state': 'enabled',
            'rules': [
                # Block common attack vectors
                {'port': 4444, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block Metasploit'},
                {'port': 4444, 'protocol': 'tcp', 'direction': 'out', 'action': 'block', 'name': 'Block Metasploit Out'},
                {'port': 31337, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block Back Orifice'},
                {'port': 12345, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block NetBus'},
                {'port': 23, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block Telnet'},
                {'port': 135, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block RPC'},
                {'port': 139, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block NetBIOS'},
                {'port': 445, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block SMB'},
                {'port': 3389, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block RDP (if not needed)'},
            ],
            'allow_icmp': False,
            'block_incoming': True
        },
        ProfileType.GAMING: {
            'name': 'Gaming',
            'emoji': '🎮',
            'description': 'Low latency - essential gaming ports open',
            'firewall_state': 'enabled',
            'rules': [
                # Common gaming ports - allow inbound for multiplayer
                {'port': 3074, 'protocol': 'udp', 'direction': 'both', 'action': 'allow', 'name': 'Xbox Live'},
                {'port': 3478, 'protocol': 'udp', 'direction': 'both', 'action': 'allow', 'name': 'STUN'},
                {'port': 3479, 'protocol': 'udp', 'direction': 'both', 'action': 'allow', 'name': 'PlayStation Network'},
                {'port': 3480, 'protocol': 'udp', 'direction': 'both', 'action': 'allow', 'name': 'PlayStation Network'},
                {'port': 25565, 'protocol': 'tcp', 'direction': 'in', 'action': 'allow', 'name': 'Minecraft Server'},
                {'port': 27015, 'protocol': 'udp', 'direction': 'both', 'action': 'allow', 'name': 'Steam'},
                # Block common attack vectors but allow gaming
                {'port': 4444, 'protocol': 'tcp', 'direction': 'in', 'action': 'block', 'name': 'Block Metasploit'},
            ],
            'allow_icmp': True,
            'block_incoming': False
        }
    }
    
    def __init__(self):
        """Initialize profile manager"""
        self.firewall = FirewallManager()
        self._current_profile = None
        self._applied_rules = []
        
    def get_available_profiles(self) -> List[Dict]:
        """
        Get list of available profiles
        
        Returns:
            List of profile information dictionaries
        """
        profiles = []
        for profile_type, config in self.PROFILES.items():
            profiles.append({
                'id': profile_type.value,
                'name': config['name'],
                'emoji': config['emoji'],
                'description': config['description']
            })
        return profiles
        
    def get_current_profile(self) -> Optional[str]:
        """Get the currently active profile"""
        return self._current_profile
        
    def apply_profile(self, profile_name: str, auto_backup: bool = True) -> Tuple[bool, str]:
        """
        Apply a firewall profile
        
        Args:
            profile_name: Profile identifier ('open', 'balanced', 'strict', 'gaming')
            auto_backup: Whether to backup rules before applying
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Find profile
            profile_type = None
            for ptype in ProfileType:
                if ptype.value.lower() == profile_name.lower():
                    profile_type = ptype
                    break
                    
            if not profile_type:
                return False, f"Unknown profile: {profile_name}. Available: open, balanced, strict, gaming"
                
            config = self.PROFILES[profile_type]
            
            # Backup current rules if requested
            if auto_backup:
                success, filepath = self.firewall.export_rules()
                if success:
                    logger.info(f"Backup created: {filepath}")
                    
            # Clear previously applied rules from this profile
            self._clear_profile_rules()
            
            # Apply firewall state
            if config['firewall_state'] == 'enabled':
                success, msg = self.firewall.enable_firewall('all')
                if not success:
                    logger.warning(f"Failed to enable firewall: {msg}")
            else:
                success, msg = self.firewall.disable_firewall('all')
                if not success:
                    logger.warning(f"Failed to disable firewall: {msg}")
                    
            # Apply profile rules
            applied_rules = []
            for rule_config in config['rules']:
                # Handle 'both' direction by creating two rules
                directions = ['in', 'out'] if rule_config.get('direction') == 'both' else [rule_config.get('direction')]
                
                for direction in directions:
                    rule_name = rule_config.get('name', f"Profile {profile_type.value}")
                    
                    success, msg = self.firewall.create_rule(
                        name=f"[Profile] {rule_name}",
                        direction=direction,
                        action=rule_config.get('action', 'allow'),
                        protocol=rule_config.get('protocol', 'tcp'),
                        port=rule_config.get('port'),
                        description=f"Applied by {config['name']} profile"
                    )
                    
                    if success:
                        applied_rules.append(f"[Profile] {rule_name}")
                        
            self._applied_rules = applied_rules
            self._current_profile = profile_type.value
            
            emoji = config['emoji']
            name = config['name']
            rule_count = len(applied_rules)
            
            logger.info(f"Applied profile: {name} with {rule_count} rules")
            return True, f"{emoji} Profile '{name}' applied - {rule_count} rules configured"
            
        except Exception as e:
            logger.error(f"Failed to apply profile: {e}")
            return False, f"Error applying profile: {str(e)}"
            
    def _clear_profile_rules(self):
        """Clear rules applied by the current profile"""
        for rule_name in self._applied_rules:
            try:
                self.firewall.delete_rule(rule_name)
            except Exception as e:
                logger.warning(f"Failed to remove rule {rule_name}: {e}")
        self._applied_rules = []
        
    def switch_profile(self, profile_name: str) -> Tuple[bool, str]:
        """
        Switch to a different profile (clears current and applies new)
        
        Args:
            profile_name: Target profile
            
        Returns:
            Tuple of (success, message)
        """
        return self.apply_profile(profile_name)
        
    def get_profile_info(self, profile_name: str) -> Optional[Dict]:
        """
        Get detailed information about a profile
        
        Args:
            profile_name: Profile identifier
            
        Returns:
            Profile configuration dictionary or None
        """
        for ptype in ProfileType:
            if ptype.value.lower() == profile_name.lower():
                config = self.PROFILES[ptype].copy()
                config['id'] = ptype.value
                return config
        return None
        
    def is_profile_active(self, profile_name: str) -> bool:
        """
        Check if a profile is currently active
        
        Args:
            profile_name: Profile to check
            
        Returns:
            True if the profile is currently active
        """
        return self._current_profile == profile_name.lower()


# Singleton instance
_profile_manager = None

def get_profile_manager() -> ProfileManager:
    """Get singleton profile manager instance"""
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = ProfileManager()
    return _profile_manager
