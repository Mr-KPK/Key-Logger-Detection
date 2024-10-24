import psutil
import win32api
import win32con
import win32gui
import ctypes
import os

# Detect processes that may be keyloggers by looking at their names or libraries
def detect_keylogger():
    # List of suspicious process names to look for (this list can be extended)
    suspicious_processes = ['keylogger', 'pynput', 'keyboard', 'hook']
    found_keylogger = False

    # Iterate through all running processes
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_name = proc.info['name'].lower()
            # Check for suspicious processes by name
            if any(suspicious in process_name for suspicious in suspicious_processes):
                print(f"[!] Suspicious Process Detected: {process_name} (PID: {proc.info['pid']})")
                found_keylogger = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if not found_keylogger:
        print("No suspicious keylogger process detected.")

# Detect global keyboard hooks (Windows-specific)
def detect_keyboard_hook():
    user32 = ctypes.windll.user32
    hooks = user32.GetKeyboardLayout(0)
    if hooks:
        print(f"[!] Keyboard hook detected: {hooks}")
    else:
        print("No global keyboard hooks detected.")

# Detect if a specific window belongs to a keylogger (by checking titles or windows running in the background)
def detect_suspicious_window():
    # Get the current window
    window_handle = win32gui.GetForegroundWindow()
    window_title = win32gui.GetWindowText(window_handle)

    # Check if the window title indicates suspicious activity
    if 'keylogger' in window_title.lower():
        print(f"[!] Suspicious window detected: {window_title}")
    else:
        print("No suspicious windows detected.")

# Main function to run all detection methods
def detect_keylogger_activity():
    print("Scanning for potential keyloggers...\n")
    
    # Detect suspicious processes
    detect_keylogger()

    # Detect global keyboard hooks
    detect_keyboard_hook()

    # Detect suspicious windows
    detect_suspicious_window()

# Run the detection script
if __name__ == "__main__":
    detect_keylogger_activity()
