import psutil
import logging


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
    logging.info(" Network Info:")
    net_io = psutil.net_io_counters()
    logging.info(f" Total Bytes Sent: {net_io.bytes_sent / (1024 ** 2):.2f} MB")
    logging.info(f" Total Bytes Received: {net_io.bytes_recv / (1024 ** 2):.2f} MB\n")

def disc():
    #Disk information
    logging.info("Disk Info:")
    for partition in psutil.disk_partitions():
        logging.info(f"Device: {partition.device}")
        logging.info(f"  Mountpoint: {partition.mountpoint}")
        logging.info(f"  File system type: {partition.fstype}")
        usage = psutil.disk_usage(partition.mountpoint)
        logging.info(f"  Total Size: {usage.total / (1024 ** 3):.2f} GB")
        logging.info(f"  Used: {usage.used / (1024 ** 3):.2f} GB")
        logging.info(f"  Free: {usage.free / (1024 ** 3):.2f} GB")
        logging.info(f"  Percentage: {usage.percent}%")