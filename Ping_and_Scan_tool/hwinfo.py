import psutil
import logging
import os
import time
from psutil._common import bytes2human


def log_hardware_info():

    # CPU information
    logging.info("CPU Info:")
    logging.info(f" Physical cores: {psutil.cpu_count(logical=False)}")
    logging.info(f" Total cores: {psutil.cpu_count(logical=True)}")
    logging.info(f" Max Frequency: {psutil.cpu_freq().max}Mhz")
    logging.info(f" Min Frequency: {psutil.cpu_freq().min}Mhz")
    logging.info(f" Current Frequency: {psutil.cpu_freq().current}Mhz")
    logging.info(f" CPU Usage Per Core: {psutil.cpu_percent(percpu=True)}")
    logging.info(f" Total CPU Usage: {psutil.cpu_percent()}%\n")

    # Memory information
    logging.info("Memory Info:")
    virtual_memory = psutil.virtual_memory()
    logging.info(f" Total: {virtual_memory.total / (1024 ** 3):.2f} GB")
    logging.info(f" Available: {virtual_memory.available / (1024 ** 3):.2f} GB")
    logging.info(f" Used: {virtual_memory.used / (1024 ** 3):.2f} GB")
    logging.info(f" Percentage: {virtual_memory.percent}%\n")

    # Network information
    logging.info("Network Info:")
    net_io = psutil.net_io_counters()
    logging.info(f" Total Bytes Sent: {net_io.bytes_sent / (1024 ** 2):.2f} MB")
    logging.info(f" Total Bytes Received: {net_io.bytes_recv / (1024 ** 2):.2f} MB\n")

    #Disk information
    templ = "{:<17} {:>8} {:>8} {:>8} {:>5}% {:>9}  {}"
    logging.info(f'{templ.format("Device", "Total", "Used", "Free", "Use ", "Type", "Mount")}')
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
            part.mountpoint,
        )
        logging.info(f'{line}')