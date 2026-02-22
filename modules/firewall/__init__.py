"""
PC-Omnifix Firewall Module
==========================

Enterprise-grade Windows Firewall Management & Protection Engine.

Features:
- Firewall status checking and auditing
- Smart rule management (create, delete, enable, disable)
- Preset profiles (Open, Balanced, Strict, Gaming)
- Network threat monitoring
- Rollback capabilities

Author: PC-Omnifix
Version: 1.0.0
"""

from .firewall_manager import (
    FirewallManager,
    get_firewall_manager,
    ProfileType,
    RuleDirection,
    RuleAction,
    Protocol
)

from .profiles import (
    ProfileManager,
    get_profile_manager
)

from .audit import (
    FirewallAuditor,
    get_auditor
)

from .rollback import (
    RollbackManager,
    get_rollback_manager
)

from .monitor import (
    NetworkMonitor,
    get_network_monitor
)

__all__ = [
    # Firewall Manager
    'FirewallManager',
    'get_firewall_manager',
    'ProfileType',
    'RuleDirection',
    'RuleAction',
    'Protocol',
    
    # Profiles
    'ProfileManager',
    'get_profile_manager',
    
    # Audit
    'FirewallAuditor',
    'get_auditor',
    
    # Rollback
    'RollbackManager',
    'get_rollback_manager',
    
    # Monitor
    'NetworkMonitor',
    'get_network_monitor',
]

__version__ = '1.0.0'
