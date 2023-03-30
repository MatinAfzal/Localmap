############################################################################
# LOCAl MAP Created By Matin Afzal
# https://github.com/MatinAfzal
# contact.matin@yahoo.com
############################################################################

############################################################################
# DISCLAIMER: This tool is made only to increase the knowledge 
# and security of the internal network, The responsibility of 
# any unethical and illegal use of this tool is on user!
############################################################################

###################################-HELP-###################################
# C: means class 
# F: means function 
# FF: means a function that should only be called by another function 
# EJ: means extra work that the module does (Extra job)
############################################################################

############################################################################
# F: getAliveHosts(): It sends a ping request to a list of possible hosts
# and the active hosts it finds are added to the alive_hosts list.
# F: portScan() : It performs the high-speed port scanning process through
# the following three (FF) functions:
# FF: PS_getPorts()
# FF: PS_scanThread()
# FF: PS_scan():
# EJ: And finally, by using the OSFingerprinting module, it identifies the
# target system
############################################################################

import subprocess
import socket
import IPFingerprinting
from queue import Queue
from threading import Thread, Lock
from colorama import init, Fore
from tqdm import tqdm
from IPDiscovery import IPDiscovery

# File identity information
__author__ = 'Matin Afzal (contact.matin@yahoo.com)'
__version__ = '0.0.2'
__last_modification__ = '2023/03/27'

# Class assignment
queue = Queue()
print_lock = Lock()
IP = IPDiscovery()

# Assigning coloroma colors
init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

# Required file variables
temp_open_ports = []

def getAliveHosts(possible_hosts, host_os='Windows', packet_count=1, wait=10):
    """
    possible_hosts : A list of possible hosts on the network to check
    Creates a complete list of active hosts in the network
    -host_os : host operation system Linux / Windows / Mac
    -packet_count : Number of packets sent to find live host
    -wait : Waiting time to receive a response from the host in milliseconds
    +returns : alive_hosts
    """

    # getAliveHosts() Variables
    found_hosts = 0
    alive_hosts = []

    # Specify the appropriate switch for the operating system
    # '-n' for windows & mac - '-c' for Linux
    if host_os == 'Linux':
        host_switch = '-c'
    else:
        host_switch = '-n'
    
    progression_bar = tqdm(possible_hosts)

    for host in progression_bar:
        if host_os == "Linux":
            ping = subprocess.Popen("ping {} {} -w {} {}".format(host_switch, packet_count, wait, host), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            exit_code = ping.wait()
        else:
            ping = subprocess.Popen("ping {} {} -w {} {}".format(host_switch, packet_count, wait, host), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            exit_code = ping.wait()

        if exit_code != 0:
            pass
        else:
            found_hosts += 1
            alive_hosts.append(host)
        
        progression_bar.set_description(f"Found hosts: {found_hosts}")
            
    return alive_hosts

def portScan(alive_hosts, port_range=False, **kwargs):
    """
    A function that, by calling 3 other functions, performs the process of
    scanning open ports for each host in the list of live hosts.
    -alive_hosts : A list of active hosts
    -range : Specifies the port range selection mode
    -**kwargs : -start_range and -end_range
    """

    # Global host variable for other functions to access this variable
    global host, temp_open_ports

    # portScan() Variables
    # range of all TCP/IP ports
    range_list = [ port for port in range(0, 65535)]
    steps = 0

    if port_range:
        start_range = kwargs["start_range"]
        end_range = kwargs["end_range"]
        range_list = range_list[start_range:end_range]

    for host in alive_hosts:

        host_total_steps = len(alive_hosts)
        steps += 1

        IP.IP = host
        IP.getMAC()
        IP.getMacManufacturer()

        try:
            host_name = socket.gethostbyaddr(host)
            host_name = host_name[0]
        except:
            host_name = "Not Found"

        print(f"\nChecking host [{steps}/{host_total_steps}] : Host: {host} Host name: {host_name}\tMac address: {IP.mac} Mac manufacturer: {IP.mac_manufacturer}")

        # calling 3 other functions
        PS_getPorts(host, range_list)

        if temp_open_ports:
            try: 
                os_fingerprint = IPFingerprinting.OSFingerprint(host, temp_open_ports)
            except:
                print(f"\n\tThere was no result in checking the fingerprint of the operating system")
            else:
                if os_fingerprint != None:
                    print(f"\n\tOS Fingerprint : {os_fingerprint}")
                else:
                     print(f"\n\tThere was no result in checking the fingerprint of the operating system")

        temp_open_ports = []

############################################################################
# The functions created from here on should only be called by the portScan()
# function and each other, respectively. No external file can call these, 
# otherwise an error will occur.
############################################################################

def PS_getPorts(host, port_range):

    global queue

    for thread in range(200):
        thread = Thread(target=PS_scanThread)
        thread.daemon = True
        thread.start()

    for worker in port_range:
        queue.put(worker)

    queue.join()

def PS_scanThread():

    global queue

    while True:
        worker = queue.get()
        PS_scan(worker)
        queue.task_done()

def PS_scan(port):

    try:
        client = socket.socket()
        client.connect((host, port))
    except:
        with print_lock:
            print(f"\t{GRAY}{host:15}:{port:5} is ...{RESET}", end='\r')
    else:
        with print_lock:
            try:
                service_name = socket.getservbyport(port, 'tcp')
            except:
                service_name = "Not found"
            temp_open_ports.append(port)
            print(f"\t{GREEN}{host:15}:{port:5} is open\tService name: {service_name}\t{RESET}")