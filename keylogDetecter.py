import psutil
import ctypes
import os
import time
from win32evtlog import OpenEventLog, ReadEventLog, EVENTLOG_BACKWARDS_READ, EVENTLOG_SEQUENTIAL_READ

# Detect processes using suspicious libraries
def detect_suspicious_processes():
    suspicious_keywords = ['pynput', 'keyboard', 'keylogger', 'hook']
    found_suspicious_process = False

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_info = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
            if any(keyword in process_info for keyword in suspicious_keywords):
                print(f"[!] Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})")
                found_suspicious_process = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not found_suspicious_process:
        print("No suspicious processes detected.")

# Detect keyboard hooks (Windows-specific)
def detect_keyboard_hook():
    user32 = ctypes.windll.user32
    hooks = user32.GetKeyboardLayout(0)

    if hooks:
        print(f"[!] Keyboard hook detected: {hooks}")
    else:
        print("No global keyboard hooks detected.")

# Monitor CPU and memory usage of suspicious processes
def monitor_system_resources():
    suspicious_processes = []
    threshold_cpu = 50.0  # Example CPU usage threshold in percent
    threshold_memory = 50.0  # Example memory usage threshold in MB

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            if proc.info['cpu_percent'] > threshold_cpu or proc.info['memory_info'].rss / (1024 * 1024) > threshold_memory:
                print(f"[!] High resource usage detected in process: {proc.info['name']} (PID: {proc.info['pid']})")
                suspicious_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not suspicious_processes:
        print("No suspicious resource-consuming processes detected.")

# Detect suspicious files being created (e.g., log files)
def detect_suspicious_files():
    suspicious_directories = [os.getenv('TEMP'), os.getenv('APPDATA')]
    suspicious_file_patterns = ['key_log.txt', 'key_log.json', 'keylog']
    found_files = []

    for directory in suspicious_directories:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(pattern in file.lower() for pattern in suspicious_file_patterns):
                        found_files.append(os.path.join(root, file))

    if found_files:
        for file in found_files:
            print(f"[!] Suspicious file detected: {file}")
    else:
        print("No suspicious log files detected.")

# Monitor network activity of processes (basic monitoring)
def monitor_network_activity():
    suspicious_ports = [80, 443]  # Example suspicious ports (HTTP, HTTPS)
    suspicious_connections = []

    for conn in psutil.net_connections():
        if conn.status == psutil.CONN_ESTABLISHED and conn.laddr.port in suspicious_ports:
            proc = psutil.Process(conn.pid)
            suspicious_connections.append(proc)

    if suspicious_connections:
        for proc in suspicious_connections:
            print(f"[!] Suspicious network activity detected: {proc.name()} (PID: {proc.pid})")
    else:
        print("No suspicious network activity detected.")

# Scan Windows Event Logs for suspicious activity
def detect_windows_event_log_activities():
    log_handle = OpenEventLog(None, 'Application')
    flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ
    events = ReadEventLog(log_handle, flags, 0)

    suspicious_keywords = ['keyboard', 'keylogger', 'hook', 'pynput']
    for event in events:
        event_message = str(event.StringInserts)
        if any(keyword in event_message.lower() for keyword in suspicious_keywords):
            print(f"[!] Suspicious event log detected: {event_message}")

# Main function to run all detection mechanisms
def detect_keylogger_activity():
    print("Starting keylogger detection...\n")

    # Detect suspicious processes
    detect_suspicious_processes()

    # Detect keyboard hooks
    detect_keyboard_hook()

    # Monitor CPU and memory usage
    monitor_system_resources()

    # Detect suspicious files
    detect_suspicious_files()

    # Monitor network activity
    monitor_network_activity()

    # Scan Windows Event Logs for suspicious activities
    detect_windows_event_log_activities()

    print("\nKeylogger detection completed.")

if __name__ == "__main__":
    detect_keylogger_activity()
