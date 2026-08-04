"""
Database Backup and Maintenance Script
"""

import sqlite3
import shutil
import os
from datetime import datetime

class DatabaseBackup:
    def __init__(self, db_path='database/malware_sandbox.db', backup_dir='database/backups'):
        self.db_path = db_path
        self.backup_dir = backup_dir
        os.makedirs(backup_dir, exist_ok=True)
    
    def backup(self):
        """Create a backup of the database"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.backup_dir, f'malware_sandbox_{timestamp}.db')
        
        try:
            shutil.copy2(self.db_path, backup_file)
            print(f"[✓] Backup created: {backup_file}")
            return backup_file
        except Exception as e:
            print(f"[✗] Backup failed: {e}")
            return None
    
    def restore(self, backup_file):
        """Restore database from backup"""
        if not os.path.exists(backup_file):
            print(f"[✗] Backup file not found: {backup_file}")
            return False
        
        try:
            # Create a backup of current database before restoring
            self.backup()
            
            shutil.copy2(backup_file, self.db_path)
            print(f"[✓] Database restored from: {backup_file}")
            return True
        except Exception as e:
            print(f"[✗] Restore failed: {e}")
            return False
    
    def list_backups(self):
        """List all available backups"""
        backups = []
        if os.path.exists(self.backup_dir):
            for file in sorted(os.listdir(self.backup_dir)):
                if file.endswith('.db'):
                    filepath = os.path.join(self.backup_dir, file)
                    size = os.path.getsize(filepath)
                    backups.append({
                        'filename': file,
                        'size': size,
                        'size_mb': round(size / (1024 * 1024), 2),
                        'date': file.replace('malware_sandbox_', '').replace('.db', '')
                    })
        return backups
    
    def cleanup_old_backups(self, keep=10):
        """Keep only the most recent backups"""
        backups = sorted(os.listdir(self.backup_dir))
        backups = [b for b in backups if b.endswith('.db')]
        
        if len(backups) > keep:
            for old_backup in backups[:-keep]:
                os.remove(os.path.join(self.backup_dir, old_backup))
                print(f"[✓] Removed old backup: {old_backup}")

if __name__ == "__main__":
    backup_manager = DatabaseBackup()
    
    # Create a backup
    backup_manager.backup()
    
    # List backups
    print("\nExisting backups:")
    for backup in backup_manager.list_backups():
        print(f"  - {backup['filename']} ({backup['size_mb']} MB)")
    
    # Cleanup old backups (keep last 10)
    backup_manager.cleanup_old_backups(keep=10)

