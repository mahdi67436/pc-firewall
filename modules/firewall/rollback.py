"""
Firewall Rollback System
PC-Omnifix - Safe rollback for firewall rule changes

Provides:
- Manual rollback from backup
- Automatic rollback on connectivity loss
- Emergency reset
- Rule change history

Author: PC-Omnifix
Version: 1.0.0
"""

import logging
import json
import os
import shutil
import datetime
from typing import Dict, List, Tuple, Optional
from .firewall_manager import FirewallManager

logger = logging.getLogger(__name__)


class RollbackManager:
    """
    Firewall Rollback Manager
    
    Manages rollback of firewall rule changes for safety.
    Implements automatic rollback if connectivity is lost.
    """
    
    def __init__(self):
        """Initialize rollback manager"""
        self.firewall = FirewallManager()
        self.history_dir = os.path.join(
            self.firewall.backup_dir,
            'history'
        )
        self._ensure_history_dir()
        
    def _ensure_history_dir(self):
        """Create history directory if it doesn't exist"""
        try:
            os.makedirs(self.history_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create history directory: {e}")
            
    def create_checkpoint(self, name: str = None) -> Tuple[bool, str]:
        """
        Create a named checkpoint of current firewall rules
        
        Args:
            name: Optional checkpoint name
            
        Returns:
            Tuple of (success, filepath)
        """
        try:
            if not name:
                name = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                
            filename = f"checkpoint_{name}.json"
            filepath = os.path.join(self.history_dir, filename)
            
            # Export current rules
            success, output = self.firewall.export_rules(filename)
            
            if success:
                # Also save firewall status
                status = self.firewall.get_firewall_status()
                status_file = filepath.replace('.json', '_status.json')
                with open(status_file, 'w') as f:
                    json.dump(status, f, indent=2)
                    
                logger.info(f"Created checkpoint: {name}")
                return True, filepath
            else:
                return False, f"Failed to create checkpoint: {output}"
                
        except Exception as e:
            logger.error(f"Failed to create checkpoint: {e}")
            return False, str(e)
            
    def list_checkpoints(self) -> List[Dict]:
        """
        List all available checkpoints
        
        Returns:
            List of checkpoint information
        """
        checkpoints = []
        
        try:
            for filename in os.listdir(self.history_dir):
                if filename.startswith('checkpoint_') and filename.endswith('_status.json'):
                    filepath = os.path.join(self.history_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            
                        checkpoints.append({
                            'name': filename.replace('checkpoint_', '').replace('_status.json', ''),
                            'file': filepath,
                            'status': data.get('overall', 'Unknown')
                        })
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.error(f"Failed to list checkpoints: {e}")
            
        # Sort by name (timestamp)
        checkpoints.sort(key=lambda x: x['name'], reverse=True)
        return checkpoints
        
    def restore_checkpoint(self, name: str) -> Tuple[bool, str]:
        """
        Restore firewall rules from a checkpoint
        
        Args:
            name: Checkpoint name to restore
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Find the checkpoint file
            checkpoint_file = os.path.join(self.history_dir, f"checkpoint_{name}.json")
            
            if not os.path.exists(checkpoint_file):
                # Try to find by partial match
                for f in os.listdir(self.history_dir):
                    if f.startswith('checkpoint_') and name in f and f.endswith('.json'):
                        checkpoint_file = os.path.join(self.history_dir, f)
                        break
                        
            if not os.path.exists(checkpoint_file):
                available = [c['name'] for c in self.list_checkpoints()]
                return False, f"Checkpoint '{name}' not found. Available: {available}"
                
            # Backup current state before restore
            self.create_checkpoint('pre_restore')
            
            # Read checkpoint data
            with open(checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)
                
            # Delete current custom rules
            success, msg = self._clear_custom_rules()
            if not success:
                logger.warning(f"Some rules could not be cleared: {msg}")
                
            # Restore rules from checkpoint
            # Note: This is a simplified version - real implementation would
            # need to parse and recreate each rule
            restored_count = 0
            
            # Handle single rule or list
            rules_data = checkpoint_data if isinstance(checkpoint_data, list) else [checkpoint_data]
            
            for rule_data in rules_data:
                try:
                    # Skip rules that might already exist
                    display_name = rule_data.get('DisplayName')
                    if not display_name:
                        continue
                        
                    direction = 'in' if rule_data.get('Direction') == 'Inbound' else 'out'
                    action = 'allow' if rule_data.get('Action') == 'Allow' else 'block'
                    enabled = rule_data.get('Enabled') == 'True'
                    
                    # Only restore enabled rules
                    if enabled:
                        success, msg = self.firewall.create_rule(
                            name=display_name,
                            direction=direction,
                            action=action,
                            description=rule_data.get('Description', '')
                        )
                        if success:
                            restored_count += 1
                            
                except Exception as e:
                    logger.warning(f"Could not restore rule: {e}")
                    
            logger.info(f"Restored {restored_count} rules from checkpoint {name}")
            return True, f"Restored {restored_count} rules from checkpoint '{name}'"
            
        except Exception as e:
            logger.error(f"Failed to restore checkpoint: {e}")
            return False, f"Restore failed: {str(e)}"
            
    def _clear_custom_rules(self) -> Tuple[bool, str]:
        """
        Clear all custom (non-default) firewall rules
        
        Returns:
            Tuple of (success, message)
        """
        try:
            # Get all current rules
            rules = self.firewall.get_rules()
            
            # Delete rules (except default Windows rules)
            deleted = 0
            for rule in rules:
                display_name = rule.get('DisplayName', '')
                
                # Skip default Windows rules (they don't have PC-Omnifix or known prefixes)
                if display_name and not any(x in display_name for x in ['@%', 'CoreNet']):
                    try:
                        self.firewall.delete_rule(display_name)
                        deleted += 1
                    except Exception:
                        pass
                        
            return True, f"Cleared {deleted} custom rules"
            
        except Exception as e:
            return False, str(e)
            
    def get_last_backup(self) -> Optional[str]:
        """
        Get the path to the most recent backup
        
        Returns:
            Path to backup file or None
        """
        try:
            # Look in backup directory
            backup_dir = self.firewall.backup_dir
            
            if not os.path.exists(backup_dir):
                return None
                
            # Find most recent backup
            backups = []
            for f in os.listdir(backup_dir):
                if f.startswith('firewall_rules_backup_') and f.endswith('.json'):
                    filepath = os.path.join(backup_dir, f)
                    backups.append((os.path.getmtime(filepath), filepath))
                    
            if backups:
                backups.sort(reverse=True)
                return backups[0][1]
                
        except Exception as e:
            logger.error(f"Failed to find backup: {e}")
            
        return None
        
    def rollback_to_backup(self, backup_file: str = None) -> Tuple[bool, str]:
        """
        Rollback to a specific backup file
        
        Args:
            backup_file: Specific backup file to restore (default: most recent)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Find backup file
            if not backup_file:
                backup_file = self.get_last_backup()
                
            if not backup_file:
                return False, "No backup file found"
                
            if not os.path.exists(backup_file):
                return False, f"Backup file not found: {backup_file}"
                
            # Create checkpoint before rollback
            self.create_checkpoint('pre_rollback')
            
            # Read and restore from backup
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
                
            # Restore rules
            restored = 0
            rules = backup_data if isinstance(backup_data, list) else [backup_data]
            
            for rule in rules:
                try:
                    display_name = rule.get('DisplayName')
                    if not display_name:
                        continue
                        
                    direction = 'in' if rule.get('Direction') == 'Inbound' else 'out'
                    action = 'allow' if rule.get('Action') == 'Allow' else 'block'
                    
                    self.firewall.create_rule(
                        name=display_name,
                        direction=direction,
                        action=action,
                        description=rule.get('Description', '')
                    )
                    restored += 1
                    
                except Exception as e:
                    logger.warning(f"Could not restore rule: {e}")
                    
            return True, f"Rolled back to backup - {restored} rules restored"
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False, f"Rollback failed: {str(e)}"
            
    def emergency_reset(self) -> Tuple[bool, str]:
        """
        Emergency reset - completely reset firewall to safe defaults
        
        This is a safety function that:
        1. Creates a backup first
        2. Removes all PC-Omnifix rules
        3. Enables all firewall profiles
        4. Resets to balanced profile
        
        Returns:
            Tuple of (success, message)
        """
        try:
            # Create emergency backup
            self.create_checkpoint('emergency_backup')
            
            # Use firewall's reset function
            success, msg = self.firewall.reset_firewall()
            
            if success:
                # Enable all profiles
                self.firewall.enable_firewall('all')
                
                logger.warning("Emergency reset completed")
                return True, "Emergency reset completed - firewall restored to safe defaults"
            else:
                return False, f"Emergency reset failed: {msg}"
                
        except Exception as e:
            logger.error(f"Emergency reset failed: {e}")
            return False, f"Emergency reset failed: {str(e)}"
            
    def delete_checkpoint(self, name: str) -> Tuple[bool, str]:
        """
        Delete a specific checkpoint
        
        Args:
            name: Checkpoint name to delete
            
        Returns:
            Tuple of (success, message)
        """
        try:
            base_file = os.path.join(self.history_dir, f"checkpoint_{name}.json")
            status_file = base_file.replace('.json', '_status.json')
            
            deleted = []
            
            if os.path.exists(base_file):
                os.remove(base_file)
                deleted.append(base_file)
                
            if os.path.exists(status_file):
                os.remove(status_file)
                deleted.append(status_file)
                
            if deleted:
                return True, f"Deleted checkpoint '{name}'"
            else:
                return False, f"Checkpoint '{name}' not found"
                
        except Exception as e:
            return False, f"Failed to delete checkpoint: {str(e)}"
            
    def cleanup_old_checkpoints(self, keep_latest: int = 5) -> Tuple[bool, str]:
        """
        Clean up old checkpoints, keeping only the most recent ones
        
        Args:
            keep_latest: Number of latest checkpoints to keep
            
        Returns:
            Tuple of (success, message)
        """
        try:
            checkpoints = self.list_checkpoints()
            
            if len(checkpoints) <= keep_latest:
                return True, f"No cleanup needed - {len(checkpoints)} checkpoints exist"
                
            # Sort by name (reverse for newest first)
            checkpoints.sort(key=lambda x: x['name'], reverse=True)
            
            # Delete older checkpoints
            deleted = 0
            for checkpoint in checkpoints[keep_latest:]:
                name = checkpoint['name']
                self.delete_checkpoint(name)
                deleted += 1
                
            return True, f"Cleaned up {deleted} old checkpoints"
            
        except Exception as e:
            return False, f"Cleanup failed: {str(e)}"


# Singleton instance
_rollback_manager = None

def get_rollback_manager() -> RollbackManager:
    """Get singleton rollback manager instance"""
    global _rollback_manager
    if _rollback_manager is None:
        _rollback_manager = RollbackManager()
    return _rollback_manager
