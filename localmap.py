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

############################################################################
# The local map is a tool for detailed and general examination of your local
# network. This tool can prepare a complete profile of other devices on the 
# network that is run on any host in the network.
# Some of the activities of this tool:
# - Detection of the local address of the local map host.
# - Preparation of a complete list of possible hosts on the network.
# - Detection of active hosts on the network.
# - Identification of network card information and their manufacturer for
#   each active host in the network.
# - Checking the open ports of any active host on the network.
# - Detect and guess the operating system of any active host on the network.
############################################################################

###################################-HELP-###################################
# C: means class 
# F: means function 
# FF: means a function that should only be called by another function  
# EJ: means extra work that the module does (Extra job)
############################################################################

############################################################################
# F: localMapBanner(): Banner of the tool to display in the output of 
# command lines.
# F: UILocalIP(): If the user wants to enter the IP manually, it will be
# received from the user.
# F: UILocalPrefix(): It receives the network IP prefix from the user.
# F: UIRange(): It receives the host or port range from the user.
# F: possibleHostList(): This function performs the complete process of 
# generating lists of possible hosts.
# F: aliveHostList(): This function performs the complate process of
# generating lists od alive hosts.
# F: clearDeployBanner(): clear terminal and deploy tool banner.
############################################################################

import os
import ipaddress
from IPDiscovery import IPDiscovery
from IPScanning import getAliveHosts, portScan
from colorama import init, Fore
from platform import system
from PackageCheck import packageListCheck

# File identity information
__author__ = 'Matin Afzal (contact.matin@yahoo.com)'
__version__ = '0.0.1'
__last_modification__ = '2023/03/28'

# Class assignment
IP = IPDiscovery()

# Assigning coloroma colors
init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

# List of required packages for all local map files
required_packages = ["colorama", "mac_vendor_lookup", "scapy", "tqdm"]

def localMapBanner():
    print("""
    ██╗      ██████╗  ██████╗ █████╗ ██╗         ███╗   ███╗ █████╗ ██████╗ 
    ██║     ██╔═══██╗██╔════╝██╔══██╗██║         ████╗ ████║██╔══██╗██╔══██╗
    ██║     ██║   ██║██║     ███████║██║         ██╔████╔██║███████║██████╔╝
    ██║     ██║   ██║██║     ██╔══██║██║         ██║╚██╔╝██║██╔══██║██╔═══╝ 
    ███████╗╚██████╔╝╚██████╗██║  ██║███████╗    ██║ ╚═╝ ██║██║  ██║██║     
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  
        Created by Matin Afzal
        github: https://github.com/MatinAfzal   
    """)

# The functions that are created here have the task of receiving and
# verifying the correct input from the user.

def UILocalIP():
    """
    USER INPUT
    +returns: decision, user_ip 
    """

    while True:
        print(f"{GREEN}[UserInput]{RESET}: Do you want to enter your local IP address manually? (Our suggestion is no).")
        decision = input("[Y / N] ---> ").lower()

        if decision == 'y':

            while True:
                print(f"{GREEN}[UserInput]{RESET}: Please enter the local address of the device that LOCAL MAP is on.")
                user_ip = input("[IP] ---> ")
                try:
                    ipaddress.ip_address(user_ip)
                except:
                    print(f"{RED}[InputError]{RESET}: The IP address entered is not correct.")
                    continue
                else:
                    decision = True
                    return decision, user_ip
                

        elif decision == 'n':
            decision = False
            user_ip = ''
            return decision, user_ip
        else:
            print(f"{RED}[InputError]{RESET}: Entered value must Y or N.")
            continue


def UILocalPrefix(local_ip):
    """
    USER INPUT
    -local_ip : Local address of the host
    +returns : prefix
    """

    while True:
        print(f"{GREEN}[UserInput]{RESET}: Your local IP address is {local_ip} Please specify your IP prefix.")
        ui_prefix = input("[8 / 16 / 24] ---> ")

        if ui_prefix == '8':
            return ui_prefix
        elif ui_prefix == '16':
            return ui_prefix
        elif ui_prefix == '24':
            return ui_prefix
        else:
            print(f"{RED}[InputError]{RESET}: Entered prefix must be 8, 16 or 24.")
            continue

def UIRange(length, for_port=False):
    """
    USER INPUT
    -length : The total length anything
    -for_port : Determines whether to value the port range or not
    +returns : start_range, end_range
    """

    # UIHostRange() Variables
    start_range_in_range = False
    end_range_in_range = False

    while True:
        if for_port:
            msg = "ports"
        else:
            msg = "hosts on your network"
        print(f"{GREEN}[UserInput]{RESET}: There are {length} possible {msg}! do you want to check them all? Note that this process may take a long time!")
        ui_decision = input("[Y / N] ---> ").lower()

        if ui_decision == 'y':
            if for_port:
                start_range = 1
                end_range = 65535
            else:
                start_range = 0
                end_range = length
            return start_range, end_range
        
        elif ui_decision == 'n':
            while True:
                print(f"{GREEN}[UserInput]{RESET}: Where does the range start?")
                start_range = input(f"[?-{length}] ---> ")

                try:
                    start_range = int(start_range)
                except:
                    print(f"{RED}[InputError]{RESET}: Entered value must integer.")
                    continue
                else:
                    if (start_range > 0 and start_range <= length):
                        start_range_in_range = True
                        break
                    else:
                        print(f"{RED}[InputError]{RESET}: The selected area is out of range.")
                        continue
            while True:
                print(f"{GREEN}[UserInput]{RESET}: Where does the range ends?")
                end_range = input(f"[{start_range}-?] ---> ")
                
                try:
                    end_range = int(end_range)
                except:
                    print(f"{RED}[InputError]{RESET}: Entered value must integer.")
                    continue
                else:
                    if (end_range > 0 and end_range <= length):
                        end_range_in_range = True
                        break
                    else:
                        print(f"{RED}[InputError]{RESET}: The selected area is out of range.")
                        continue
                
            if start_range_in_range and end_range_in_range:
                return start_range, end_range
                
        else:
            os.system("cls" or "clear")
            localMapBanner()
            print(f"{RED}[InputError]{RESET}: Entered value must Y or N.")
            continue

# The functions created from here divide the parts of the program into different
# functions.

def possibleHostList(manual=False, **kwargs):
    """
    USER INPUT / PROGRAM FUNCTION P1
    -manual : 
    -**kwargs : user_ip
    +returns : possible_hosts
    """

    if manual:
        user_ip = kwargs['user_ip']
    else:
        IP.getLocalIP()
        user_ip = IP.local_IP

    # possibleHostList() Variables
    prefix = UILocalPrefix(user_ip)

    IP.prefix = prefix
    if IP.prefix == '8':
        total_range = 16777216
    elif IP.prefix == '16':
        total_range =  65536
    elif IP.prefix == '24':
        total_range = 256

    start_range, end_range = UIRange(total_range)

    IP.local_IP = user_ip
    IP.getPossibleHosts(host_range=True, start_range=start_range, end_range=end_range)

    return IP.possible_hosts

def aliveHostList(possible_hosts):
    """
    USER INPUT / PROGRAM FUNCTION P2
    -possible_hosts : list of possible hosts in the network
    +returns : alive_hosts
    """

    try:
        host_os = system() # 'Windows' for Linux it prints 'Linux', Mac it prints `'Darwin'
    except:
        host_os = 'Windows' #default
    
    print(f"""{GREEN}[Attention]{RESET}: By default, this tool waits only 10 milliseconds for a response from hosts in the network! 
This may cause many hosts not to be found! You can change the default value of this via the wait variable in the 
localmap.py file (scanning may take much longer)""")
    alive_hosts = getAliveHosts(possible_hosts, host_os=host_os, packet_count=1, wait=10)
    return alive_hosts

def aliveHostsPorts(alive_hosts):
    """
    USER INPUT / PROGRAM FUNCTION P3
    -alive_hosts : list of alive hosts in the network.
    """

    # aliveHostList() Variables
    start_range, end_range = UIRange(65535, for_port=True)
    clearDeployBanner()

    portScan(alive_hosts, port_range=True, start_range=start_range, end_range=end_range)

def clearDeployBanner():
    """
    Clear terminal and deploy banner again
    """

    try:
        host_os = system() # 'Windows' for Linux it prints 'Linux', Mac it prints `'Darwin'
    except:
        host_os = 'Windows' #default

    if host_os == "Linux":
        os.system('clear')
    else:
        os.system('cls')

    localMapBanner()

# main source of function calls
if __name__ == "__main__":

    localMapBanner()

    packageListCheck(required_packages)

    decision, user_ip = UILocalIP()
    possible_hosts = possibleHostList(manual=decision, user_ip=user_ip)
    clearDeployBanner()

    alive_hosts = aliveHostList(possible_hosts)

    aliveHostsPorts(alive_hosts)
    
    console_get = input("Enter any key: ")
