import os
import sys
import logging
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import socket
import struct
import getpass
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import reporter



class FileAuditHandler(FileSystemEventHandler):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.recently_created_files = {}
        self._last_modified_time = {}
        self.temporary_file_map = {}

    def on_created(self, event):
        if ".goutputstream" in os.path.basename(event.src_path):
            original_path = self.find_original_file(event.src_path)
            if original_path:
                self.temporary_file_map[event.src_path] = original_path
                self.logger.info(f"Временный файл создан: {event.src_path} (исходный файл изменился: {original_path})")
        elif event.is_directory:
            self.logger.info(f"Создана папка: {event.src_path}")
        else:
            self.logger.info(f"Создан файл: {event.src_path}")

    def on_deleted(self, event):
        if ".goutputstream" in os.path.basename(event.src_path):
            return

        if event.is_directory:
            self.logger.info(f"Удалена папка: {event.src_path}")
        else:
            self.logger.info(f"Удалён файл: {event.src_path}")
            try:
                subject = "Уведомление: файл удалён"
                body = f"Файл '{event.src_path}' был удалён."
                recipient_email = "battlevegan@gmail.com"
                send_email(subject, body, recipient_email)
            except Exception as e:
                self.logger.error(f"Ошибка при отправке уведомления: {e}")

    def on_moved(self, event):
        if ".goutputstream" in os.path.basename(event.src_path):
            return

        src_dir = os.path.dirname(event.src_path)
        dest_dir = os.path.dirname(event.dest_path)

        if src_dir == dest_dir:
            self.logger.info(f"Файл переименован: {event.src_path} → {event.dest_path}")
        else:
            self.logger.info(f"Файл перемещён: {event.src_path} → {event.dest_path}")

    def find_original_file(self, temp_path):
        base_name = temp_path.split('.goutputstream')[0]
        if os.path.exists(base_name):
            return base_name
        return None


def monitor_processes(logger):
    known_pids = set()

    while True:
        current_pids = set(pid for pid in os.listdir('/proc') if pid.isdigit())

        new_pids = current_pids - known_pids
        terminated_pids = known_pids - current_pids

        for pid in new_pids:
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmd = f.read().replace('\x00', ' ').strip()
                if not cmd:
                    logger.info(f"Запущен процесс: PID={pid}, команда отсутствует")
                else:
                    logger.info(f"Запущен процесс: PID={pid}, команда: {cmd}")
            except FileNotFoundError:
                continue

        for pid in terminated_pids:
            logger.info(f"Завершён процесс: PID={pid}")

        known_pids = current_pids
        time.sleep(1)


def hex_to_ip(hex_ip):
    try:
        return socket.inet_ntoa(struct.pack("<L", int(hex_ip, 16)))
    except ValueError:
        return "Invalid IP"


def monitor_network(logger):
    def read_connections(protocol):
        with open(f"/proc/net/{protocol}", "r") as f:
            return f.readlines()[1:]

    while True:
        tcp_connections = read_connections("tcp")
        udp_connections = read_connections("udp")

        for conn in tcp_connections:
            parts = conn.split()
            local_ip, local_port = parts[1].split(':')
            logger.info(f"TCP соединение: {hex_to_ip(local_ip)}:{int(local_port, 16)}")

        for conn in udp_connections:
            parts = conn.split()
            local_ip, local_port = parts[1].split(':')
            logger.info(f"UDP соединение: {hex_to_ip(local_ip)}:{int(local_port, 16)}")

        time.sleep(5)


def setup_logger(log_file, name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(log_file, encoding="utf-8")

    username = os.getenv("LOGNAME") or os.getenv("USER") or "unknown_user"

    formatter = logging.Formatter(f'%(asctime)s - {username} - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def send_email(subject, body, to_email):
    SMTP_SERVER = "smtp.yandex.ru"
    SMTP_PORT = 587
    EMAIL = "Yourway-XM@yandex.ru"
    PASSWORD = "nioszjmxpznmkmyd"

    try:
        
        msg = MIMEMultipart()
        msg["From"] = EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo
            server.starttls()
            server.ehlo()
            server.login(EMAIL, PASSWORD)
            server.sendmail(EMAIL, to_email, msg.as_string())

        print(f"Уведомление отправлено на {to_email}")
    except Exception as e:
        print(f"Ошибка при отправке уведомления: {e}")


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 audit_tool.py <путь_к_папке>")
        sys.exit(1)

    path = sys.argv[1]

    if not os.path.exists(path) or not os.path.isdir(path):
        print(f"Ошибка: Указанный путь '{path}' не существует или не является папкой.")
        sys.exit(1)

    file_logger = setup_logger("file_system_log.txt", "FileSystem")
    process_logger = setup_logger("process_log.txt", "Process")
    network_logger = setup_logger("network_log.txt", "Network")

    file_logger.info(f"Запуск мониторинга папки: {path}")

    threading.Thread(target=monitor_processes, args=(process_logger,), daemon=True).start()

    threading.Thread(target=monitor_network, args=(network_logger,), daemon=True).start()

    event_handler = FileAuditHandler(file_logger)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    try:
        observer.start()
        print(f"Мониторинг изменений в папке '{path}' запущен. Нажмите Ctrl+C для завершения.")
        observer.join()
    except KeyboardInterrupt:
        reporter.create_excel_report('file_system_log.txt', 'network_log.txt', 'process_log.txt', f"report{time.time()}.xlsx")
        observer.stop()
        print("\nМониторинг остановлен.")
    observer.join()


if __name__ == "__main__":
    main()


