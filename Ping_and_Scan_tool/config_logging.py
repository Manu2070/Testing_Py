import os
import logging
import sys
import configparser
import tkinter as tk
from datetime import datetime

ts = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

# --- Class ---
class TextHandler(logging.Handler):
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.widget.insert(tk.END, msg + '\n', record.levelname)
            self.widget.see(tk.END)
        self.widget.after(0, append)

def get_ini_file_path(file_name):
    # Check if running as a bundled exe
    if getattr(sys, 'frozen', False):
        # If frozen (compiled), use the bundled resource path
        base_path = sys._MEIPASS
    else:
        # If not bundled, use the current working directory
        base_path = os.path.dirname(__file__)

    # Check if the operating system is Windows
    if os.name == 'nt':
        base_path = base_path.replace('/', base_path)
    else:
        base_path = base_path.replace('\\', base_path)    
    
    return os.path.join(base_path, file_name)

def read_config():
    # Get paths for the two config files
    settings_path = get_ini_file_path('settings.ini')
    ports_path = get_ini_file_path('ports.ini')

    logging.debug(f"[{ts}] [{settings_path}] found")
    logging.debug(f"[{ts}] [{ports_path}] found\n")
    
    # Read both config files
    config = configparser.ConfigParser()
    config.read(settings_path)
    if not config.sections():
        logging.error(f"[{ts}] [Settings file not loaded or is empty!]\n")
    
    config_port = configparser.ConfigParser()
    config_port.read(ports_path)
    if not config_port.sections():
        logging.error(f"[{ts}] [Ports file not loaded or is empty!]\n")
    
    return config, config_port

def setup_logging():
    log_dir = os.path.join('Ping_and_Scan_tool', 'log')
    os.makedirs(log_dir, exist_ok=True)  # Ensure the directory exists
    log_file = datetime.now().strftime(f"ping_tool_%d-%m-%Y.log")  # Log file with date and time
    log_file_path = os.path.join(log_dir, log_file)
    log_fh = logging.FileHandler(log_file_path)  # File handler
    log_sh = logging.StreamHandler(sys.stdout)  # Stream handler
    log_format = logging.Formatter('%(levelname)s - %(message)s')  # Log format
    log_fh.setFormatter(log_format)  # Set format to file handler
    log_sh.setFormatter(log_format)  # Set format to stream handler
    logging.basicConfig(level=logging.INFO)  # Basic configuration
    logging.getLogger().addHandler(log_fh)
    logging.getLogger().addHandler(log_sh)  