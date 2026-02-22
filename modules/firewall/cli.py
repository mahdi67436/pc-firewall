"""
Firewall CLI Commands
=====================

CLI commands for PC-Omnifix firewall management.

Commands:
    firewall status              - Check firewall status
    firewall enable              - Enable firewall
    firewall disable             - Disable firewall
    firewall profile <name>      - Switch firewall profile
    firewall allow --app <path>  - Allow application
    firewall block --port <num>  - Block port
    firewall rules --list        - List rules
    firewall audit               - Run security audit
    firewall rollback            - Rollback changes
    firewall reset               - Emergency reset
    firewall monitor             - Network monitoring

Author: PC-Omnifix
Version: 1.0.0
"""

import argparse
import sys
import logging
import io
from typing import Optional

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass  # Fallback if encoding fix fails

from .firewall_manager import get_firewall_manager
from .profiles import get_profile_manager
from .audit import get_auditor
from .rollback import get_rollback_manager
from .monitor import get_network_monitor

logger = logging.getLogger(__name__)


def cmd_status(args) -> int:
    """Show firewall status"""
    firewall = get_firewall_manager()
    status = firewall.get_firewall_status()
    
    print("\n" + "="*50)
    print("       🛡️  WINDOWS FIREWALL STATUS")
    print("="*50)
    print(f"\n  Domain:  {'✓ Enabled' if status['domain']['enabled'] else '✗ Disabled'}")
    print(f"  Private: {'✓ Enabled' if status['private']['enabled'] else '✗ Disabled'}")
    print(f"  Public:  {'✓ Enabled' if status['public']['enabled'] else '✗ Disabled'}")
    print(f"\n  Overall: {status['overall']}")
    print("\n" + "="*50 + "\n")
    
    return 0


def cmd_enable(args) -> int:
    """Enable firewall"""
    firewall = get_firewall_manager()
    profile = args.profile if hasattr(args, 'profile') else 'all'
    
    success, message = firewall.enable_firewall(profile)
    
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        
    return 0 if success else 1


def cmd_disable(args) -> int:
    """Disable firewall"""
    firewall = get_firewall_manager()
    profile = args.profile if hasattr(args, 'profile') else 'all'
    
    success, message = firewall.disable_firewall(profile)
    
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        
    return 0 if success else 1


def cmd_profile(args) -> int:
    """Switch firewall profile"""
    profile_manager = get_profile_manager()
    profile_name = args.profile_name
    
    # List available profiles if none specified
    if profile_name == 'list':
        profiles = profile_manager.get_available_profiles()
        print("\n" + "="*50)
        print("       🎯 AVAILABLE FIREWALL PROFILES")
        print("="*50)
        
        for p in profiles:
            print(f"\n  {p['emoji']} {p['name']}")
            print(f"     {p['description']}")
            
        print("\n" + "="*50 + "\n")
        return 0
        
    # Apply profile
    success, message = profile_manager.apply_profile(profile_name)
    
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        print("\nAvailable profiles: open, balanced, strict, gaming")
        
    return 0 if success else 1


def cmd_allow(args) -> int:
    """Allow application through firewall"""
    firewall = get_firewall_manager()
    
    if args.app:
        app_path = args.app
        success, message = firewall.allow_app(app_path, name=args.name)
    else:
        print("✗ Error: --app parameter required")
        return 1
        
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        
    return 0 if success else 1


def cmd_block(args) -> int:
    """Block port or application"""
    firewall = get_firewall_manager()
    
    if args.port:
        port = args.port
        direction = args.direction or 'in'
        protocol = args.protocol or 'tcp'
        
        success, message = firewall.block_port(port, direction, protocol)
    elif args.app:
        # Block by removing rules or adding block rule
        print("✗ Application blocking not yet implemented")
        return 1
    else:
        print("✗ Error: --port or --app parameter required")
        return 1
        
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        
    return 0 if success else 1


def cmd_rules(args) -> int:
    """List or manage firewall rules"""
    firewall = get_firewall_manager()
    
    if args.list:
        # List rules
        direction = args.direction
        enabled_only = args.enabled_only
        
        rules = firewall.get_rules(direction, enabled_only)
        
        print("\n" + "="*50)
        print("       📋 FIREWALL RULES")
        print("="*50)
        
        if not rules:
            print("\n  No rules found")
        else:
            print(f"\n  Total rules: {len(rules)}\n")
            
            for i, rule in enumerate(rules[:50], 1):  # Show first 50
                enabled = "✓" if rule.get('Enabled') == 'True' else "✗"
                direction = "↓" if rule.get('Direction') == 'Inbound' else "↑"
                action = "✓" if rule.get('Action') == 'Allow' else "✗"
                name = rule.get('DisplayName', 'Unknown')[:40]
                
                print(f"  {i:2}. {enabled} {direction} {action} {name}")
                
            if len(rules) > 50:
                print(f"\n  ... and {len(rules) - 50} more rules")
                
        print("\n" + "="*50 + "\n")
        
    elif args.export:
        # Export rules
        success, filepath = firewall.export_rules()
        
        if success:
            print(f"✓ Rules exported to: {filepath}")
        else:
            print(f"✗ Export failed: {filepath}")
            return 1
            
    return 0


def cmd_audit(args) -> int:
    """Run firewall security audit"""
    auditor = get_auditor()
    
    # Run full audit
    audit = auditor.run_full_audit()
    
    # Print summary
    auditor.print_audit_summary()
    
    # Export if requested
    if args.export:
        success, filepath = auditor.export_audit_report()
        if success:
            print(f"✓ Audit report exported to: {filepath}")
            
    return 0


def cmd_rollback(args) -> int:
    """Rollback firewall changes"""
    rollback = get_rollback_manager()
    
    if args.checkpoint:
        # Create checkpoint
        success, message = rollback.create_checkpoint(args.checkpoint)
    elif args.restore:
        # Restore checkpoint
        success, message = rollback.restore_checkpoint(args.restore)
    elif args.list:
        # List checkpoints
        checkpoints = rollback.list_checkpoints()
        
        print("\n" + "="*50)
        print("       📦 FIREWALL CHECKPOINTS")
        print("="*50)
        
        if not checkpoints:
            print("\n  No checkpoints found")
        else:
            for cp in checkpoints:
                print(f"\n  {cp['name']}")
                print(f"     Status: {cp['status']}")
                
        print("\n" + "="*50 + "\n")
        return 0
    elif args.backup:
        # Rollback to backup
        success, message = rollback.rollback_to_backup(args.backup)
    else:
        # List recent backup and offer rollback
        last_backup = rollback.get_last_backup()
        if last_backup:
            print(f"Most recent backup: {last_backup}")
            print("Use --backup to rollback to this backup")
        else:
            print("No backup files found")
        return 0
        
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        
    return 0 if success else 1


def cmd_reset(args) -> int:
    """Emergency firewall reset"""
    rollback = get_rollback_manager()
    
    if args.safe:
        # Safe reset - just remove PC-Omnifix rules
        success, message = rollback.emergency_reset()
    else:
        # Confirm required for full reset
        print("⚠️  This will reset the firewall to default Windows settings.")
        print("   All custom rules will be removed.")
        print("\n   Use --safe flag for a safe reset (removes only PC-Omnifix rules)")
        print("   Or type 'yes' to confirm full reset:")
        
        confirm = input("   > ")
        
        if confirm.lower() == 'yes':
            success, message = rollback.emergency_reset()
        else:
            print("   Reset cancelled")
            return 0
            
    if success:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        
    return 0 if success else 1


def cmd_monitor(args) -> int:
    """Network threat monitoring"""
    monitor = get_network_monitor()
    
    if args.start:
        # Start monitoring
        interval = args.interval or 60
        monitor.start_monitoring(interval)
        print(f"✓ Network monitoring started (interval: {interval}s)")
        
    elif args.stop:
        # Stop monitoring
        monitor.stop_monitoring()
        print("✓ Network monitoring stopped")
        
    elif args.scan:
        # One-time scan
        print("\n" + "="*50)
        print("       🔍 NETWORK THREAT SCAN")
        print("="*50 + "\n")
        
        results = monitor.scan_for_threats()
        
        print(f"  Listening ports: {len(results['listening_ports'])}")
        print(f"  Active connections: {results.get('active_connections', 'N/A')}")
        
        if results['suspicious_ports']:
            print(f"\n  ⚠️  Suspicious ports detected:")
            for sp in results['suspicious_ports']:
                print(f"     Port {sp['port']}: {sp['threat']} ({sp['process']})")
                
        if results['high_connection_processes']:
            print(f"\n  ⚡ High connection processes:")
            for hp in results['high_connection_processes']:
                print(f"     {hp['process']}: {hp['connections']} connections")
                
        print("\n  Recommendations:")
        for rec in results['recommendations']:
            print(f"     {rec}")
            
        print("\n" + "="*50 + "\n")
        
    elif args.status:
        # Show monitoring status
        summary = monitor.get_network_summary()
        
        print("\n" + "="*50)
        print("       📊 NETWORK MONITOR STATUS")
        print("="*50)
        
        print(f"\n  Monitoring active: {'Yes' if summary.get('is_monitoring') else 'No'}")
        print(f"  Listening ports: {summary.get('listening_count', 0)}")
        print(f"  Active connections: {summary.get('active_connections', 0)}")
        print(f"  Unique processes: {summary.get('unique_processes', 0)}")
        print(f"  Suspicious ports: {summary.get('suspicious_ports', 0)}")
        print(f"  Recent alerts: {summary.get('recent_alerts', 0)}")
        
        print("\n" + "="*50 + "\n")
        
    else:
        # Show help
        print("Use --start, --stop, --scan, or --status")
        
    return 0


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description='PC-Omnifix Firewall Manager',
        prog='pc-omnifix firewall'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Firewall commands')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check firewall status')
    status_parser.set_defaults(func=cmd_status)
    
    # Enable command
    enable_parser = subparsers.add_parser('enable', help='Enable firewall')
    enable_parser.add_argument('--profile', default='all', help='Profile to enable (domain/private/public/all)')
    enable_parser.set_defaults(func=cmd_enable)
    
    # Disable command
    disable_parser = subparsers.add_parser('disable', help='Disable firewall')
    disable_parser.add_argument('--profile', default='all', help='Profile to disable (domain/private/public/all)')
    disable_parser.set_defaults(func=cmd_disable)
    
    # Profile command
    profile_parser = subparsers.add_parser('profile', help='Switch firewall profile')
    profile_parser.add_argument('profile_name', nargs='?', default='list', help='Profile name (open/balanced/strict/gaming)')
    profile_parser.set_defaults(func=cmd_profile)
    
    # Allow command
    allow_parser = subparsers.add_parser('allow', help='Allow application through firewall')
    allow_parser.add_argument('--app', required=True, help='Application path')
    allow_parser.add_argument('--name', help='Optional rule name')
    allow_parser.add_argument('--direction', default='out', choices=['in', 'out'], help='Direction')
    allow_parser.set_defaults(func=cmd_allow)
    
    # Block command
    block_parser = subparsers.add_parser('block', help='Block port or application')
    block_parser.add_argument('--port', type=int, help='Port number to block')
    block_parser.add_argument('--app', help='Application to block')
    block_parser.add_argument('--direction', default='in', choices=['in', 'out'], help='Direction')
    block_parser.add_argument('--protocol', default='tcp', choices=['tcp', 'udp'], help='Protocol')
    block_parser.set_defaults(func=cmd_block)
    
    # Rules command
    rules_parser = subparsers.add_parser('rules', help='Manage firewall rules')
    rules_parser.add_argument('--list', action='store_true', help='List rules')
    rules_parser.add_argument('--export', action='store_true', help='Export rules')
    rules_parser.add_argument('--direction', choices=['in', 'out'], help='Filter by direction')
    rules_parser.add_argument('--enabled-only', action='store_true', help='Show only enabled rules')
    rules_parser.set_defaults(func=cmd_rules)
    
    # Audit command
    audit_parser = subparsers.add_parser('audit', help='Run security audit')
    audit_parser.add_argument('--export', action='store_true', help='Export audit report')
    audit_parser.set_defaults(func=cmd_audit)
    
    # Rollback command
    rollback_parser = subparsers.add_parser('rollback', help='Rollback changes')
    rollback_parser.add_argument('--checkpoint', help='Create checkpoint with name')
    rollback_parser.add_argument('--restore', help='Restore checkpoint by name')
    rollback_parser.add_argument('--list', action='store_true', help='List checkpoints')
    rollback_parser.add_argument('--backup', nargs='?', const='latest', help='Rollback to backup')
    rollback_parser.set_defaults(func=cmd_rollback)
    
    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Emergency firewall reset')
    reset_parser.add_argument('--safe', action='store_true', help='Safe reset (only removes PC-Omnifix rules)')
    reset_parser.set_defaults(func=cmd_reset)
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Network threat monitoring')
    monitor_parser.add_argument('--start', action='store_true', help='Start monitoring')
    monitor_parser.add_argument('--stop', action='store_true', help='Stop monitoring')
    monitor_parser.add_argument('--scan', action='store_true', help='Run threat scan')
    monitor_parser.add_argument('--status', action='store_true', help='Show monitoring status')
    monitor_parser.add_argument('--interval', type=int, help='Check interval in seconds')
    monitor_parser.set_defaults(func=cmd_monitor)
    
    return parser


def main(args=None):
    """Main CLI entry point"""
    parser = create_parser()
    parsed = parser.parse_args(args)
    
    if not parsed.command:
        parser.print_help()
        return 1
        
    return parsed.func(parsed)


if __name__ == '__main__':
    sys.exit(main())
