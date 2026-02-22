"""
Network Threat Monitor
PC-Omnifix - Lightweight network monitoring for firewall security

Provides:
- Detection of excessive outbound connections
- Suspicious port monitoring
- Unexpected listening service alerts
- Log-only monitoring (no packet sniffing)

Author: PC-Omnifix
Version: 1.0.0
"""

import logging
import json
import subprocess
import time
import os
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from threading import Thread, Event

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Lightweight Network Threat Monitor
    
    Monitors network activity for suspicious patterns without
    packet sniffing - only reads Windows API data.
    """
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {
        4444: 'Metasploit',
        31337: 'Back Orifice',
        12345: 'NetBus',
        54321: 'NetBus',
        1337: 'Leet/Common RAT',
        6667: 'IRC (potential botnet)',
        4443: 'Metasploit HTTPS',
        5555: 'Android ADB/RAT',
        6666: 'IRC Bot',
        6665: 'IRC Bot'
    }
    
    # Maximum connections per minute before alerting
    CONNECTION_THRESHOLD = 50
    
    # Common legitimate processes
    LEGITIMATE_PROCESSES = [
        'chrome.exe',
        'firefox.exe',
        'msedge.exe',
        'svchost.exe',
        'System',
        'lsass.exe',
        'services.exe'
    ]
    
    def __init__(self):
        """Initialize network monitor"""
        self._monitoring = False
        self._stop_event = Event()
        self._monitor_thread = None
        self._alerts = []
        self._connection_history = {}
        
    def start_monitoring(self, interval: int = 60):
        """
        Start background network monitoring
        
        Args:
            interval: Check interval in seconds
        """
        if self._monitoring:
            logger.warning("Monitoring already running")
            return
            
        self._stop_event.clear()
        self._monitor_thread = Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self._monitor_thread.start()
        self._monitoring = True
        logger.info("Network monitoring started")
        
    def stop_monitoring(self):
        """Stop background network monitoring"""
        if not self._monitoring:
            return
            
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        self._monitoring = False
        logger.info("Network monitoring stopped")
        
    def _monitor_loop(self, interval: int):
        """Main monitoring loop"""
        while not self._stop_event.is_set():
            try:
                # Check for suspicious activity
                self._check_listening_ports()
                self._check_connection_patterns()
                
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                
            # Wait for next interval
            self._stop_event.wait(interval)
            
    def _check_listening_ports(self):
        """Check for suspicious listening ports"""
        try:
            listening = self.get_listening_ports()
            
            for item in listening:
                port = item.get('port')
                if port in self.SUSPICIOUS_PORTS:
                    alert = {
                        'type': 'suspicious_port',
                        'port': port,
                        'process': item.get('process', 'Unknown'),
                        'malware': self.SUSPICIOUS_PORTS[port],
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'high'
                    }
                    self._add_alert(alert)
                    logger.warning(f"Suspicious port detected: {port} ({self.SUSPICIOUS_PORTS[port]})")
                    
        except Exception as e:
            logger.error(f"Error checking listening ports: {e}")
            
    def _check_connection_patterns(self):
        """Check for excessive connection patterns"""
        try:
            connections = self.get_active_connections()
            
            # Group by process
            process_counts = {}
            for conn in connections:
                proc = conn.get('process', 'Unknown')
                process_counts[proc] = process_counts.get(proc, 0) + 1
                
            # Check for excessive connections
            for proc, count in process_counts.items():
                if count > self.CONNECTION_THRESHOLD:
                    alert = {
                        'type': 'excessive_connections',
                        'process': proc,
                        'count': count,
                        'threshold': self.CONNECTION_THRESHOLD,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'medium'
                    }
                    self._add_alert(alert)
                    logger.warning(f"Excessive connections from {proc}: {count}")
                    
        except Exception as e:
            logger.error(f"Error checking connections: {e}")
            
    def _add_alert(self, alert: Dict):
        """Add alert to history"""
        self._alerts.append(alert)
        # Keep only last 100 alerts
        if len(self._alerts) > 100:
            self._alerts = self._alerts[-100:]
            
    def get_listening_ports(self) -> List[Dict]:
        """
        Get list of ports with listening services
        
        Returns:
            List of listening port information
        """
        listening = []
        
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '''Get-NetTCPConnection -State Listen | 
                 Select-Object LocalAddress, LocalPort, OwningProcess | 
                 ConvertTo-Json'''],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    connections = data if isinstance(data, list) else [data]
                    
                    for conn in connections:
                        proc_name = self._get_process_name(conn.get('OwningProcess'))
                        
                        listening.append({
                            'port': conn.get('LocalPort'),
                            'address': conn.get('LocalAddress'),
                            'pid': conn.get('OwningProcess'),
                            'process': proc_name,
                            'suspicious': conn.get('LocalPort') in self.SUSPICIOUS_PORTS
                        })
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.error(f"Failed to get listening ports: {e}")
            
        return listening
        
    def get_active_connections(self) -> List[Dict]:
        """
        Get list of active network connections
        
        Returns:
            List of connection information
        """
        connections = []
        
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '''Get-NetTCPConnection -State Established | 
                 Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | 
                 ConvertTo-Json'''],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    connections = data if isinstance(data, list) else [data]
                    
                    for conn in connections:
                        proc_name = self._get_process_name(conn.get('OwningProcess'))
                        
                        connections.append({
                            'local_port': conn.get('LocalPort'),
                            'local_address': conn.get('LocalAddress'),
                            'remote_port': conn.get('RemotePort'),
                            'remote_address': conn.get('RemoteAddress'),
                            'pid': conn.get('OwningProcess'),
                            'process': proc_name
                        })
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.error(f"Failed to get connections: {e}")
            
        return connections
        
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            if not pid:
                return 'Unknown'
                
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout.strip() or 'Unknown'
                
        except Exception:
            pass
            
        return 'Unknown'
        
    def get_alerts(self, since: datetime = None) -> List[Dict]:
        """
        Get alerts, optionally filtered by time
        
        Args:
            since: Only return alerts after this time
            
        Returns:
            List of alerts
        """
        if not since:
            return self._alerts.copy()
            
        return [
            alert for alert in self._alerts
            if datetime.fromisoformat(alert['timestamp']) > since
        ]
        
    def get_network_summary(self) -> Dict:
        """
        Get a summary of network activity
        
        Returns:
            Dictionary with network summary
        """
        try:
            listening = self.get_listening_ports()
            connections = self.get_active_connections()
            
            # Get unique processes
            processes = set()
            for conn in connections:
                processes.add(conn.get('process', 'Unknown'))
            for item in listening:
                processes.add(item.get('process', 'Unknown'))
                
            # Count suspicious
            suspicious_count = sum(1 for item in listening if item.get('suspicious'))
            
            return {
                'listening_count': len(listening),
                'active_connections': len(connections),
                'unique_processes': len(processes),
                'suspicious_ports': suspicious_count,
                'is_monitoring': self._monitoring,
                'recent_alerts': len(self.get_alerts(since=datetime.now() - timedelta(hours=1)))
            }
            
        except Exception as e:
            logger.error(f"Failed to get network summary: {e}")
            return {'error': str(e)}
            
    def scan_for_threats(self) -> Dict:
        """
        Perform a one-time threat scan
        
        Returns:
            Dictionary with scan results
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'listening_ports': [],
            'suspicious_ports': [],
            'high_connection_processes': [],
            'recommendations': []
        }
        
        # Check listening ports
        listening = self.get_listening_ports()
        results['listening_ports'] = listening
        
        # Find suspicious ports
        for item in listening:
            port = item.get('port')
            if port in self.SUSPICIOUS_PORTS:
                results['suspicious_ports'].append({
                    'port': port,
                    'process': item.get('process'),
                    'threat': self.SUSPICIOUS_PORTS[port]
                })
                
        # Check connection patterns
        connections = self.get_active_connections()
        
        process_counts = {}
        for conn in connections:
            proc = conn.get('process', 'Unknown')
            process_counts[proc] = process_counts.get(proc, 0) + 1
            
        for proc, count in process_counts.items():
            if count > self.CONNECTION_THRESHOLD:
                results['high_connection_processes'].append({
                    'process': proc,
                    'connections': count
                })
                
        # Generate recommendations
        if results['suspicious_ports']:
            results['recommendations'].append(
                "⚠️ Suspicious listening ports detected - investigate immediately"
            )
            
        if results['high_connection_processes']:
            results['recommendations'].append(
                f"⚡ {len(results['high_connection_processes'])} processes with excessive connections"
            )
            
        if not results['suspicious_ports'] and not results['high_connection_processes']:
            results['recommendations'].append(
                "✅ No obvious network threats detected"
            )
            
        return results
        
    def clear_alerts(self):
        """Clear all stored alerts"""
        self._alerts = []
        logger.info("Alerts cleared")


# Singleton instance
_network_monitor = None

def get_network_monitor() -> NetworkMonitor:
    """Get singleton network monitor instance"""
    global _network_monitor
    if _network_monitor is None:
        _network_monitor = NetworkMonitor()
    return _network_monitor
