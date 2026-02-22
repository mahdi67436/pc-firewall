"""
PC-Omnifix Main Application Entry Point
========================================

Main CLI integration for PC-Omnifix including firewall commands.

Author: PC-Omnifix
Version: 1.0.0
"""

import sys
import argparse
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main application entry point"""
    # Create main parser
    parser = argparse.ArgumentParser(
        description='PC-Omnifix - All-in-One PC Maintenance & Security Tool',
        prog='pc-omnifix'
    )
    
    parser.add_argument('--version', action='version', version='PC-Omnifix v1.0.0')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Add subparsers
    subparsers = parser.add_subparsers(dest='module', help='Available modules')
    
    # ============ FIREWALL MODULE ============
    firewall_parser = subparsers.add_parser(
        'firewall', 
        help='Windows Firewall Management',
        description='Manage Windows Defender Firewall'
    )
    
    firewall_subparsers = firewall_parser.add_subparsers(
        dest='firewall_command',
        help='Firewall commands'
    )
    
    # Firewall: Status
    fw_status = firewall_subparsers.add_parser('status', help='Check firewall status')
    
    # Firewall: Enable
    fw_enable = firewall_subparsers.add_parser('enable', help='Enable firewall')
    fw_enable.add_argument('--profile', default='all', 
                         choices=['domain', 'private', 'public', 'all'],
                         help='Profile to enable')
    
    # Firewall: Disable
    fw_disable = firewall_subparsers.add_parser('disable', help='Disable firewall')
    fw_disable.add_argument('--profile', default='all',
                          choices=['domain', 'private', 'public', 'all'],
                          help='Profile to disable')
    
    # Firewall: Profile
    fw_profile = firewall_subparsers.add_parser('profile', help='Switch firewall profile')
    fw_profile.add_argument('name', nargs='?', default='list',
                          help='Profile name (open, balanced, strict, gaming)')
    
    # Firewall: Allow
    fw_allow = firewall_subparsers.add_parser('allow', help='Allow application through firewall')
    fw_allow.add_argument('--app', required=True, help='Application path')
    fw_allow.add_argument('--name', help='Custom rule name')
    fw_allow.add_argument('--direction', default='out', choices=['in', 'out'],
                          help='Traffic direction')
    
    # Firewall: Block
    fw_block = firewall_subparsers.add_parser('block', help='Block port or application')
    fw_block.add_argument('--port', type=int, help='Port number to block')
    fw_block.add_argument('--app', help='Application to block')
    fw_block.add_argument('--direction', default='in', choices=['in', 'out'],
                         help='Traffic direction')
    fw_block.add_argument('--protocol', default='tcp', choices=['tcp', 'udp'],
                         help='Network protocol')
    
    # Firewall: Rules
    fw_rules = firewall_subparsers.add_parser('rules', help='Manage firewall rules')
    fw_rules.add_argument('--list', action='store_true', help='List rules')
    fw_rules.add_argument('--export', action='store_true', help='Export rules')
    fw_rules.add_argument('--direction', choices=['in', 'out'], help='Filter by direction')
    
    # Firewall: Audit
    fw_audit = firewall_subparsers.add_parser('audit', help='Run security audit')
    fw_audit.add_argument('--export', action='store_true', help='Export report')
    
    # Firewall: Rollback
    fw_rollback = firewall_subparsers.add_parser('rollback', help='Rollback changes')
    fw_rollback.add_argument('--checkpoint', help='Create checkpoint')
    fw_rollback.add_argument('--restore', help='Restore checkpoint')
    fw_rollback.add_argument('--list', action='store_true', help='List checkpoints')
    fw_rollback.add_argument('--backup', nargs='?', const='latest', help='Rollback to backup')
    
    # Firewall: Reset
    fw_reset = firewall_subparsers.add_parser('reset', help='Emergency reset')
    fw_reset.add_argument('--safe', action='store_true', help='Safe reset')
    
    # Firewall: Monitor
    fw_monitor = firewall_subparsers.add_parser('monitor', help='Network monitoring')
    fw_monitor.add_argument('--start', action='store_true', help='Start monitoring')
    fw_monitor.add_argument('--stop', action='store_true', help='Stop monitoring')
    fw_monitor.add_argument('--scan', action='store_true', help='Run threat scan')
    fw_monitor.add_argument('--status', action='store_true', help='Show status')
    
    # ============ SYSTEM MODULE (Placeholder) ============
    system_parser = subparsers.add_parser('system', help='System Information')
    system_subparsers = system_parser.add_subparsers(dest='system_command')
    system_subparsers.add_parser('info', help='System information')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle verbose
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Route to appropriate module
    if args.module == 'firewall':
        return handle_firewall(args)
    elif args.module == 'system':
        return handle_system(args)
    else:
        parser.print_help()
        return 0


def handle_firewall(args) -> int:
    """Handle firewall commands"""
    from .firewall import (
        get_firewall_manager,
        get_profile_manager,
        get_auditor,
        get_rollback_manager,
        get_network_monitor
    )
    
    cmd = args.firewall_command
    
    if not cmd:
        print("Usage: pc-omnifix firewall <command>")
        print("\nCommands:")
        print("  status        - Check firewall status")
        print("  enable        - Enable firewall")
        print("  disable       - Disable firewall")
        print("  profile       - Switch profile (open/balanced/strict/gaming)")
        print("  allow         - Allow application")
        print("  block         - Block port")
        print("  rules         - Manage rules")
        print("  audit         - Run security audit")
        print("  rollback      - Rollback changes")
        print("  reset         - Emergency reset")
        print("  monitor       - Network monitoring")
        return 0
        
    # Execute command
    if cmd == 'status':
        firewall = get_firewall_manager()
        status = firewall.get_firewall_status()
        
        print("\n" + "="*50)
        print("       🛡️  FIREWALL STATUS")
        print("="*50)
        print(f"\n  Domain:  {'✓' if status['domain']['enabled'] else '✗'}")
        print(f"  Private: {'✓' if status['private']['enabled'] else '✗'}")
        print(f"  Public:  {'✓' if status['public']['enabled'] else '✗'}")
        print(f"\n  {status['overall']}")
        print("\n" + "="*50 + "\n")
        
    elif cmd == 'enable':
        firewall = get_firewall_manager()
        success, msg = firewall.enable_firewall(args.profile)
        print(f"{'✓' if success else '✗'} {msg}")
        
    elif cmd == 'disable':
        firewall = get_firewall_manager()
        success, msg = firewall.disable_firewall(args.profile)
        print(f"{'✓' if success else '✗'} {msg}")
        
    elif cmd == 'profile':
        pm = get_profile_manager()
        
        if args.name == 'list':
            profiles = pm.get_available_profiles()
            print("\n" + "="*50)
            print("       🎯 FIREWALL PROFILES")
            print("="*50)
            for p in profiles:
                print(f"\n  {p['emoji']} {p['name']}")
                print(f"     {p['description']}")
            print("\n" + "="*50 + "\n")
        else:
            success, msg = pm.apply_profile(args.name)
            print(f"{'✓' if success else '✗'} {msg}")
            
    elif cmd == 'allow':
        firewall = get_firewall_manager()
        success, msg = firewall.allow_app(args.app, args.name, args.direction)
        print(f"{'✓' if success else '✗'} {msg}")
        
    elif cmd == 'block':
        firewall = get_firewall_manager()
        
        if args.port:
            success, msg = firewall.block_port(args.port, args.direction, args.protocol)
            print(f"{'✓' if success else '✗'} {msg}")
        else:
            print("Error: --port required")
            return 1
            
    elif cmd == 'rules':
        firewall = get_firewall_manager()
        
        if args.list:
            rules = firewall.get_rules(args.direction)
            print("\n" + "="*50)
            print("       📋 FIREWALL RULES")
            print("="*50)
            print(f"\n  Total: {len(rules)} rules\n")
            
            for i, rule in enumerate(rules[:20], 1):
                name = rule.get('DisplayName', 'Unknown')[:40]
                enabled = '✓' if rule.get('Enabled') == 'True' else '✗'
                direction = '↓' if rule.get('Direction') == 'Inbound' else '↑'
                action = '✓' if rule.get('Action') == 'Allow' else '✗'
                print(f"  {i:2}. {enabled} {direction} {action} {name}")
            print("\n" + "="*50 + "\n")
            
        elif args.export:
            success, path = firewall.export_rules()
            print(f"{'✓' if success else '✗'} Exported to: {path}")
            
    elif cmd == 'audit':
        auditor = get_auditor()
        auditor.print_audit_summary()
        
        if args.export:
            success, path = auditor.export_audit_report()
            print(f"{'✓' if success else '✗'} Report exported to: {path}")
            
    elif cmd == 'rollback':
        rollback = get_rollback_manager()
        
        if args.list:
            checkpoints = rollback.list_checkpoints()
            print("\n" + "="*50)
            print("       📦 CHECKPOINTS")
            print("="*50)
            for cp in checkpoints:
                print(f"  - {cp['name']} ({cp['status']})")
            print("\n" + "="*50 + "\n")
            
        elif args.checkpoint:
            success, path = rollback.create_checkpoint(args.checkpoint)
            print(f"{'✓' if success else '✗'} {path}")
            
        elif args.restore:
            success, msg = rollback.restore_checkpoint(args.restore)
            print(f"{'✓' if success else '✗'} {msg}")
            
        elif args.backup:
            success, msg = rollback.rollback_to_backup(args.backup)
            print(f"{'✓' if success else '✗'} {msg}")
            
        else:
            # Show available backups
            last = rollback.get_last_backup()
            print(f"Last backup: {last or 'None'}")
            print("Use --list, --checkpoint, --restore, or --backup")
            
    elif cmd == 'reset':
        rollback = get_rollback_manager()
        
        if args.safe:
            success, msg = rollback.emergency_reset()
            print(f"{'✓' if success else '✗'} {msg}")
        else:
            print("⚠️  This will reset firewall to defaults.")
            confirm = input("Type 'yes' to confirm: ")
            if confirm.lower() == 'yes':
                success, msg = rollback.emergency_reset()
                print(f"{'✓' if success else '✗'} {msg}")
            else:
                print("Cancelled")
                
    elif cmd == 'monitor':
        monitor = get_network_monitor()
        
        if args.start:
            monitor.start_monitoring()
            print("✓ Monitoring started")
            
        elif args.stop:
            monitor.stop_monitoring()
            print("✓ Monitoring stopped")
            
        elif args.scan:
            results = monitor.scan_for_threats()
            print(f"\n  Listening: {len(results['listening_ports'])}")
            print(f"  Suspicious: {len(results['suspicious_ports'])}")
            
        elif args.status:
            summary = monitor.get_network_summary()
            print(f"\n  Monitoring: {'Active' if summary.get('is_monitoring') else 'Inactive'}")
            print(f"  Listening: {summary.get('listening_count', 0)}")
            print(f"  Alerts: {summary.get('recent_alerts', 0)}")
            
        else:
            print("Use --start, --stop, --scan, or --status")
            
    return 0


def handle_system(args) -> int:
    """Handle system commands"""
    print("System module - Use 'pc-omnifix --help' for available modules")
    return 0


if __name__ == '__main__':
    sys.exit(main())
