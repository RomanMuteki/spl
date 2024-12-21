#!/usr/bin/env python3
import os
import json
import time
import logging
import shutil
import daemon
import schedule
import atexit

logging.basicConfig(
    filename='/var/log/backup_daemon.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_config():
    with open('/home/romik/sem3/demonsaregirlsbestfriends/config.json', 'r') as f:
        return json.load(f)

config = load_config()

def backup_files():
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(config['backup_directory'], f"backup_{timestamp}")

    try:
        shutil.copytree(config['source_directory'], backup_path)
        logging.info(f"Backup created at: {backup_path}")
    except Exception as e:
        logging.error(f"Error creating backup: {e}")

schedule.every(config['backup_interval']).seconds.do(backup_files)

def run_daemon():
    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    with daemon.DaemonContext():
        atexit.register(lambda: logging.info("Daemon stopped"))
        run_daemon()

if __name__ == '__main__':
    main()
