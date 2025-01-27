# Description: A simple ping/port scan tool with a GUI using tkinter, subprocess, threading, logging, and socket modules.
import os
import sys
import subprocess
import threading
import logging
import socket
import queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from config_logging import read_config, setup_logging
from hwinfo import log_hardware_info

# --- logging ---
setup_logging()

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

# --- read settings from config file ---
config, config_port = read_config()

# --- Extract settings from config file ---
windowname:str = config['WindowSettings']['windowname']
height = int(config['WindowSettings']['height'])
width = int(config['WindowSettings']['width'])
maxheight = int(config['WindowSettings']['maxheight'])
maxwidth = int(config['WindowSettings']['maxwidth'])
BG = config['BackgroundColor']['BG']
N_THREADS = int(config['ThreadSettings']['N_THREADS'])
Version = str(config['Version']['version_nm'])

logging.info(f'{sys.version}, Version: {Version}\n')

# --- Extract port descriptions from ports.ini ---
portsdes = {}
for section in config_port.sections():
    port = config_port[section]['port']
    description = config_port[section]['description']
    protocol = config_port[section]['protocol']
    portsdes[(port)] = (description, section, protocol)

# --- main ---
root = tk.Tk()
# --- Window settings ---
# - Background color -
root.configure(bg=BG)
# - Set the title of the window -
root.title(windowname)
# - Set the minimum size of the window -
root.minsize(width=width, height=height)
# - Set the maximum size of the window -
if maxwidth > 0 and maxheight > 0:
    root.maxsize(width=maxwidth, height=maxheight)

# --- Frame with Text and Scrollbar ---
frame = tk.Frame(root)
frame.grid(row=0, column=0, sticky='nsew')

box = tk.Frame(root, bg=BG)
box.grid(row=1, column=0, sticky='sew')

text = tk.Text(frame, bg=BG, fg='white')
text.grid(row=0, column=0, sticky='nsew')

scrollbar = tk.Scrollbar(frame, bg=BG)
scrollbar.grid(row=0, column=1, sticky='ns')

text['yscrollcommand'] = scrollbar.set
scrollbar['command'] = text.yview

# --- Progressbar ---
progress_bar = ttk.Progressbar(box, orient='horizontal', length=400, mode='determinate')
progress_bar.grid(row=0, column=0, pady=5, padx=5, sticky= 'ew')

# --- Version Label --- 
vl = tk.Label(box, bg=BG, fg='white', text='Version: ' + Version)
vl.grid(row=2, column=2, pady=5, padx=5, sticky= 'e')

# --- IP Address Entry ---
address = tk.Entry(master=box, bg=BG, fg='white')
address.insert(0, 'localhost')
address.bind('<Return>', lambda x: run())
address.bind('<Button-1>', lambda x: on_focus_in(address))
address.bind('<FocusOut>', lambda x: on_focus_out(address, 'localhost'))
address.config(state='disabled')
address.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)

# --- Port Entry ---  
portE = tk.Entry(master=box, bg=BG, fg='white')
portE.insert(0, 'Port')
portE.config(state='disabled')
portE.grid(row=1, column=1, sticky='nsew',  padx=5, pady=5)
portE.bind('<Button-1>', lambda x: on_focus_in(portE))
portE.bind('<FocusOut>', lambda x: on_focus_out(portE, 'Port'))

# Configure grid weights to ensure resizing
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(0, weight=1)

# Define tags for colored text
text.tag_configure("INFO", foreground="green")
text.tag_configure("WARNING", foreground="yellow")
text.tag_configure("ERROR", foreground="red")
text.tag_configure("DEBUG", foreground="blue")
text.tag_configure("CRITICAL", foreground="red", background="white")
text.tag_configure("NOM", foreground="magenta")

text_handler = TextHandler(text)
logging.getLogger().addHandler(text_handler)

# --- functions ---
log_hardware_info()

# --- Run function ---
def run(): 
    threading.Thread(target=ping).start()   # Start the ping function in a thread

# --- Ping function ---
def ping():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    address_to_ping = address.get()
    if not address_to_ping:
        logging.error(f"[{ts}] No address to ping")
        return
    logging.info(f"[{ts}] [Start ping]")
    logging.info(f"[{ts}] <----------------------------------->")
    try:
        if os.name == 'nt':  # Windows
            pull = subprocess.Popen(['ping', '-n', str(4), address_to_ping], stdout=subprocess.PIPE, bufsize=-1, text=True, shell=False)
        else:  # Unix-based
            pull = subprocess.Popen(['ping', '-c', str(4), address_to_ping], stdout=subprocess.PIPE, bufsize=-1, text=True, shell=False)
        logging.debug(f"[{ts}] [Thread:start]")
        
        while pull.poll() is None:
            for msg in pull.stdout:
                msg = msg.strip()  # read a line from the process output
                if msg:
                    logging.info(f"[{ts}] {msg}")
        logging.info(f"[{ts}] <----------------------------------->")
        logging.debug(f"[{ts}] [Thread: end]")
        logging.info(f"[{ts}] [End ping]\n")
    except Exception as e:
        logging.error(f"[{ts}] Error during ping: {e}")

# --- Port scan function ---
def port_scan():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"[{ts}] [Scan Started]")
    logging.info(f"[{ts}] <----------------------------------->")
    target = address.get()
    port_range = portE.get()
    logging.info(f"[{ts}] Scanning ports {port_range} on {target}")
    
    try:
        start_port, end_port = map(int, port_range.split('-'))
        logging.debug(f"[{ts}] Port range: {start_port} to {end_port}")
    except ValueError:
        logging.error(f"[{ts}] Invalid port range: {port_range}")
        return

    q = queue.Queue()
    logging.debug(f"[{ts}] Scanning ports {start_port} to {end_port}")

    for port in range(start_port, end_port + 1):
        q.put(port)
        logging.debug(f"[{ts}] Port {port} added to queue")

    num_threads = min(N_THREADS, os.cpu_count() * 2)  # Optimal Number of threads
    logging.info(f"[{ts}] [Number of threads: {num_threads}]\n")
    
    # Initialize progress bar
    progress_bar['maximum'] = q.qsize()
    progress_bar['value'] = 0
    
    # Start threads, each thread will call the worker function: Number of threads in settings.py
    for _ in range(num_threads):
        logging.debug(f"[{ts}] Starting thread")
        threading.Thread(target=worker, args=(target, q)).start()
    try:
        #q.join()  # Wait for all tasks to finish | won't work proberly the sript will freez don't know why
        logging.debug(f"[{ts}] All tasks finished")
    except KeyboardInterrupt:
        logging.error(f"[{ts}] Scan interrupted")
    finally:
        logging.info(f"[{ts}] <----------------------------------->")
        logging.info(f"[{ts}] [Scan Results:]\n")

# --- Worker function ---
def worker(target, q):
    while not q.empty():
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        port = q.get()
        try:
            scan_port(target, port)
        except Exception as e:
            logging.error(f"[{ts}] Error scanning port {port}: {e}")
        finally:
            q.task_done()
            # Update progress bar
            progress_bar.step(1)
            root.update_idletasks()

# --- Scan function ---
def scan_port(target, port):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    description, section, protocol = portsdes.get(str(port), ("No description available", "Unknown section", "Unknown protocol"))
    if result == 0:
        logging.warning(f"[{ts}] [{target}] Port {port} open, {description}, {protocol}, {section}")
    else:
        logging.debug(f"[{ts}] Port {port} closed")
    sock.close()

# --- Entry functions ---
def on_focus_in(entry):
    if entry.cget('state') == 'disabled':
        entry.configure(state='normal')
        entry.delete(0, 'end')

def on_focus_out(entry, placeholder):
    if entry.get() == "":
        entry.insert(0, placeholder)
        entry.configure(state='disabled')

# - button -
button = tk.Button(master=box, text='Start Ping', command=run, bg=BG, fg='white', width=20)
button.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)

# Button to start the port scan function
port_scan_button = tk.Button(box, text="Start Port Scan", command=port_scan, bg=BG, fg='white')
port_scan_button.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)

root.mainloop()