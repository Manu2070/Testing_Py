import psutil
import logging
import os
import tkinter as tk
from psutil._common import bytes2human
from config_logging import TextHandler

def log_hardware_info(text_widget):

    # CPU information
    text_widget.insert(tk.END, f"CPU Info:\n", 'DEBUG')
    text_widget.insert(tk.END, f" Physical cores: {psutil.cpu_count(logical=False)}\n")
    text_widget.insert(tk.END, f" Total cores: {psutil.cpu_count(logical=True)}\n")
    text_widget.insert(tk.END, f" Max Frequency: {psutil.cpu_freq().max}Mhz\n")
    text_widget.insert(tk.END, f" Min Frequency: {psutil.cpu_freq().min}Mhz\n")
    text_widget.insert(tk.END, f" Current Frequency: {psutil.cpu_freq().current}Mhz\n")
    text_widget.insert(tk.END, f" CPU Usage Per Core: {psutil.cpu_percent(percpu=True)}\n")
    text_widget.insert(tk.END, f" Total CPU Usage: {psutil.cpu_percent()}%\n")

    # Memory information
    text_widget.insert(tk.END, "Memory Info:\n", 'DEBUG')
    virtual_memory = psutil.virtual_memory()
    text_widget.insert(tk.END, f" Total: {virtual_memory.total / (1024 ** 3):.2f} GB\n")
    text_widget.insert(tk.END, f" Available: {virtual_memory.available / (1024 ** 3):.2f} GB\n")
    text_widget.insert(tk.END, f" Used: {virtual_memory.used / (1024 ** 3):.2f} GB\n")
    text_widget.insert(tk.END, f" Percentage: {virtual_memory.percent}%\n")

    # Network information
    text_widget.insert(tk.END, "Network Info:\n", 'DEBUG')
    net_io = psutil.net_io_counters()
    text_widget.insert(tk.END, f" Total Bytes Sent: {net_io.bytes_sent / (1024 ** 2):.2f} MB\n")
    text_widget.insert(tk.END, f" Total Bytes Received: {net_io.bytes_recv / (1024 ** 2):.2f} MB\n\n")

    #Disk information
    templ = "{:<8} {:>8} {:>8} {:>8} {:>5}% {:>9}  \n"
    text_widget.insert(tk.END, f'{templ.format("Device", "Total", "Used", "Free", "Use ", "Type")}', 'DEBUG')
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or not part.fstype:
                # skip cd-rom drives with no disk in it; they may raise
                # ENOENT, pop-up a Windows GUI error for a non-ready
                # partition or just hang.
                continue
        usage = psutil.disk_usage(part.mountpoint)
        line = templ.format(
            part.device,
            bytes2human(usage.total),
            bytes2human(usage.used),
            bytes2human(usage.free),
            int(usage.percent),
            part.fstype,
        )
        text_widget.insert(tk.END, f'{line}')