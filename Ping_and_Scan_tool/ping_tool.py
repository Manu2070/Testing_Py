# Description: A simple ping/port scan tool with a GUI using tkinter, subprocess, threading, logging, and socket modules.
import os
import sys
import subprocess
import threading
import logging
import socket
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog


import concurrent
from turtle import up
from config_logging import read_config, setup_logging, TextHandler
from hwinfo import log_hardware_info, update_hardware_info
from concurrent.futures import ThreadPoolExecutor

# --- logging ---
setup_logging()

# --- read settings from config file ---
config, config_port = read_config()

# --- Extract settings from config file ---
windowname:str = config['WindowSettings']['windowname'] # Window name
height = int(config['WindowSettings']['height']) # Window height
width = int(config['WindowSettings']['width']) # Window width
maxheight = int(config['WindowSettings']['maxheight']) # Window max height
maxwidth = int(config['WindowSettings']['maxwidth']) # Window max width
BG = config['BackgroundColor']['BG'] # Background color
N_THREADS = int(config['ThreadSettings']['N_THREADS']) # Number of threads
MIN_PORT = int(config['PortScanConstants']['MIN_PORT']) # Minimum port number
MAX_PORT = int(config['PortScanConstants']['MAX_PORT']) # Maximum port number
DEFAULT_TIMEOUT = float(config['PortScanConstants']['DEFAULT_TIMEOUT']) # seconds  
RESULT_TIMEOUT = float(config['PortScanConstants']['RESULT_TIMEOUT']) # seconds
Version = str(config['Version']['version_nm']) # Version number

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
root.configure(bg=BG, relief='flat', borderwidth=0, highlightthickness=0)
# - Set the title of the window -
root.title(windowname)
# - Set the minimum size of the window -
root.minsize(width=width, height=height)
# - Set the maximum size of the window -
if maxwidth > 0 and maxheight > 0:
    root.maxsize(width=maxwidth, height=maxheight)

# --- Frame with Text and Scrollbar ---
frame = tk.Frame(root, relief='flat', borderwidth=0, highlightthickness=0)
frame.grid(row=0, column=0, sticky='nsew')

box = tk.Frame(root, bg=BG, relief='flat', borderwidth=0, highlightthickness=0)
box.grid(row=1, column=0, sticky='sew')

text = tk.Text(frame, bg=BG, fg='white', relief='flat', borderwidth=0, highlightthickness=0)
text.grid(row=0, column=0, sticky='nsew')

hwinfo_frame = tk.Frame(frame, bg=BG)
hwinfo_frame.place(relx=0.70, rely=0.05, relwidth=0.5, relheight=0.9)
hwinfo_text = tk.Text(hwinfo_frame,wrap="word", bg=BG, fg='white', relief='flat', borderwidth=0, highlightthickness=0)
hwinfo_text.pack(expand=False, fill='both', padx=5, pady=5)

scrollbar = tk.Scrollbar(frame, bg=BG)
scrollbar.grid(row=0, column=1, sticky='ns')

text['yscrollcommand'] = scrollbar.set
scrollbar['command'] = text.yview

# --- Progressbar ---
progress_bar = ttk.Progressbar(box, orient='horizontal', length=400, mode='determinate')
progress_bar.grid(row=0, column=0, pady=5, padx=5, sticky= 'ew')

# --- Version Label --- 
vl = tk.Label(box, bg=BG, fg='white', text='System version: ' + sys.version + "\n" + 'Version: ' + Version, justify='left')
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
hwinfo_text.tag_configure("DEBUG", foreground="blue")

text_handler = TextHandler(text)
logging.getLogger().addHandler(text_handler)

# --- functions ---
logging.debug( f'Tool version: {Version}\n')
logging.debug(f'Sytem version: {sys.version}\n\n')

# Create thread pool
executor = ThreadPoolExecutor(max_workers = N_THREADS)

def start_real_time_updates():
    """
    Starts real-time updates for hardware information.
    """
    update_hardware_info(hwinfo_text)  # Update hardware info in the text widget
    root.after(1000, start_real_time_updates)  # Schedule next update after 1 second

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
    #logging.info(f"[{ts}] [Start ping]")
    text.insert(tk.END, f'[{ts}] [Start ping]\n', 'INFO')
    text.insert(tk.END, f"[{ts}] <----------------------------------->\n", 'INFO')
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
                    text.insert(tk.END, f"[{ts}] {msg}\n", 'INFO')
        text.insert(tk.END, f"[{ts}] <----------------------------------->\n", 'INFO')
        text.insert(tk.END, f'[{ts}] [End ping]\n', 'INFO')
        logging.debug(f"[{ts}] [Thread: end]")
    except Exception as e:
        logging.error(f"[{ts}] Error during ping: {e}")

# --- Port scan function ---
def port_scan():
    threading.Thread(target=port_scan_background).start()

def port_scan_background():

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = datetime.now()
    target = address.get()
    port_range = portE.get()
    completed = 0

    text.insert(tk.END, f'[{ts}] [Scan Started]\n', 'INFO')
    text.insert(tk.END, f"[{ts}] <----------------------------------->\n", 'INFO')
    text.insert(tk.END, f'[{ts}] Scanning ports {port_range} on {target}\n', 'INFO')
    
    try:
        # Validate port range
        start_port, end_port = validate_port_range(port_range)
        
        # Create work queue
        ports = list(range(start_port, end_port + 1))
        total_ports = len(ports) 
        progress_bar['maximum'] = total_ports
        progress_bar['value'] = 0
        
        # Submit scan tasks to thread pool
        scan_tasks = []
        for port in ports:
        # Process results as they complete
            try:
                future = executor.submit(scan_port, target, port)
                scan_tasks.append((port,future))
            except Exception as e:
                text.insert(tk.END,f"[{ts}] Error submitting port {port}: {str(e)}\n", 'ERROR')

        for i, (port,future) in enumerate(scan_tasks):
            try:
                future.result(timeout = RESULT_TIMEOUT * 2)
                completed += 1
            except concurrent.futures.TimeoutError:
                logging.error(f"[{ts}] Timeout scanning port {port}\n")
            except Exception as e:
                text.insert(tk.END,f"[{ts}] Error scanning port {port}: {str(e)}\n", 'ERROR')
            finally:
                progress_bar['value'] += 1
                if i % 10 == 0 or i == total_ports - 1:
                    root.update_idletasks()
                
    except ValueError as e:
        logging.error(f"[{ts}] Invalid port range {str(e)}\n")
    except Exception as e:
        logging.error(f"[{ts}] Unexpected error: {str(e)}\n")
    finally:
        end_time = datetime.now()
        elapsed_time = round((end_time - start_time).total_seconds(), 2)
        text.insert(tk.END, f"[{ts}] <----------------------------------->\n", 'INFO')
        text.insert(tk.END, f'[{ts}] Scan Complete in {elapsed_time}sec - {completed}/{total_ports} ports scanned\n', 'INFO')
        progress_bar['value'] = 0

if os.name != 'nt':
    from typing import Tuple

def validate_port_range(port_range: str) -> Tuple[int, int]:
    """Validate port range input"""
    try:
        start_port, end_port = map(int, port_range.split('-'))
        if not (MIN_PORT <= start_port <= end_port <= MAX_PORT):
            raise ValueError(f"Ports must be between {MIN_PORT} and {MAX_PORT}")
        if end_port > MAX_PORT:
            raise ValueError(f"End port can't be grater than {MAX_PORT}")
        return start_port, end_port
    except ValueError:
        raise ValueError(f"Invalid port range format. Use 'start-end' (e.g., '1-1024')")
    
# --- Scan function ---
def scan_port(target: str, port: int):
    """Scan single port"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    
    try:
        result = sock.connect_ex((target, port))
        description, section, protocol = portsdes.get(str(port), ("No description available", "Unknown section", "Unknown protocol"))
        
        if result == 0:
            text.insert(tk.END,f"[{ts}] [{target}] Port {port} open, {description}, {protocol}, {section}\n", 'WARNING')
    except Exception as e:
        text.insert(tk.END,f"[{ts}] Error scanning port {port}: {e}\n", 'ERROR')
    finally:
        sock.close()

def exprt_results():
    """Export results to a file"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"),("Text files", "*.txt")])
    if filename: 
        try:
            content = text.get("17.0", tk.END).strip().split("\n")
            total_lines = len(content)
            progress_bar['maximum'] = total_lines
            progress_bar['value'] = 0
            if filename.endswith ('.csv'):
                with open (filename, mode= "w", newline='', encoding="utf-8") as csv_file:
                    csv_writer = csv.writer(csv_file)
                    csv_writer.writerow(["Timestamp", "Target Address", "Port", "Status", "Description", "Protocol", "Section"])

                    for i, line in enumerate(content):
                        if "Port" in line and "open" in line.lower():
                                try:
                                 # Extract timestamp
                                    timestamp = line.split("]")[0].replace("[", "").strip()
                                    
                                    # Extract target address
                                    target = line.split("]")[1].split()[0].replace("[", "").strip()
                                    
                                    # Extract port number and status
                                    port_info = line.split("Port")[1].split()
                                    port = port_info[0].strip()
                                    status = port_info[1].strip().replace(",", "")
                                    
                                    # Extract description, protocol, and section
                                    remaining_info = " ".join(port_info[2:])
                                    description, protocol, section = remaining_info.split(", ")
                                    
                                    # Write row to CSV
                                    csv_writer.writerow([timestamp, target, port, status, description.strip(), protocol.strip(), section.strip()])
                                except Exception as e:
                                    logging.error(f"[{ts}] Malformed line: {line} - {e}")
                        else:
                            logging.debug(f"[{ts}] Skipped line: {line}")
                        progress_bar['value'] += 1
            else:
                with open(filename, 'w', encoding='utf-8') as txtfile:
                 txtfile.write(f"Results from {ts}\n")
                 txtfile.write(text.get("17.0", tk.END))
        except Exception as e:
            logging.error(f"[{ts}] Error exporting to {filename}: {e}\n")
        finally:
            text.insert(tk.END, f"[{ts}] Results exported to {filename}\n", "INFO")
            progress_bar['value'] = 0
            
def on_focus_in(entry):
    if entry.cget('state') == 'disabled':
        entry.configure(state='normal')
        entry.delete(0, 'end')

checkbox_var = tk.BooleanVar(value=False)

def on_checkbox_toggle():
    if checkbox_var.get():
        hwinfo_text.config(state='normal')
        hwinfo_text.delete("1.0", tk.END)
        hwinfo_text.insert(tk.END, f"Hardware Information:\n", 'INFO')
        log_hardware_info(text_widget=hwinfo_text)
        #start_real_time_updates() #todo: fix performance issue
        hwinfo_text.configure(state='disabled')
    else:
        hwinfo_text.config(state='normal')
        hwinfo_text.delete("1.0", "17.0")
        hwinfo_text.configure(state='disabled')

def on_focus_out(entry, placeholder):
    if entry.get() == "":
        entry.insert(0, placeholder)
        entry.configure(state='disabled')

def cleanup():
    """Cleanup resources"""
    executor.shutdown(wait=True)
    root.destroy()

# Function to handle window close event
def on_closing():
    cleanup()
    root.quit()


# - button -
button = tk.Button(master=box, text='Start Ping', command=run, bg=BG, fg='white', width=20)
button.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)

# Button to start the port scan function
port_scan_button = tk.Button(box, text="Start Port Scan", command=port_scan, bg=BG, fg='white')
port_scan_button.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)

# Checkbox
cbox = tk.Checkbutton(box, text='HWInfo', bg=BG, fg='white',selectcolor="black", variable=checkbox_var, command=on_checkbox_toggle)
cbox.grid(row=1, column=2, sticky='w', padx=5, pady=5)

#Menubar
menubar = tk.Menu(root, bg=BG, fg='white')
filemenu = tk.Menu(menubar, bg=BG, fg='white', tearoff=0)
menubar.add_cascade(label="File", menu=filemenu)
filemenu.add_command(label="Export", command=exprt_results)
filemenu.add_command(label="Exit", command=on_closing)

root.config(menu=menubar)

# Bind the window close event to the on_closing function
root.protocol("WM_DELETE_WINDOW", on_closing)


if __name__ == "__main__":
    root.mainloop()