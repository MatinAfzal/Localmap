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
# C: This module contains the IPDiscovery class
# Discovery class function and their tasks:
# F: getLocalIP() : Finds the local address of the host machine.
# F: getPossibleHosts() : Through the local address of the host
# and the specified IP range, it prepares a complete list of possible
# devices in the network.
# F: getMAC(): It receives the IP address of a live device in the network
# and returns its MAC address.
# F: getMacManufacturer(): It receives the MAC address of a device and
# performs a MAC Lookup to find the specifications of the network card 
# manufacturer.
############################################################################

import socket
import ipaddress
from mac_vendor_lookup import MacLookup
from scapy.layers.l2 import ARP, Ether
from scapy.all import *

# Module identity information
__author__ = "Matin Afzal (contact.matin@yahoo.com)"
__version__ = "0.0.5"
__last_modification__ = "2023/03/27"

class IPDiscovery():
    """
    A class to find IP address information
    """

    def __init__(self, prefix='16', IP=''):
        """
        Definition of IP address information variables & Attributes
        -host_os : host device operating system to assign the appropriate switches
        -prefix : prefix to specify the range of possible machines in the IP address range /8 /16 /24 
        -IP : IP address inside the network with default value = ''
        """

        # IP address inside the network
        self.IP = IP

        # getLocalIP() Variables
        self.default_local_IP = "127.0.0.1"
        self.local_IP = ''
        self.client_timeout = 0

        # getPossibleHosts() Variables
        self.prefix = prefix
        self.range_ip = []
        self.possible_hosts = []

        # getMAC() Variables
        self.mac = ''
        self.mac_manufacturer = ''


    def getLocalIP(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(self.client_timeout)
        try:
            # dosent even have to reachable
            client.connect(("10.254.254.254", 1))
            self.local_IP = client.getsockname()[0]
        except Exception:
            self.local_IP = self.default_local_IP
        finally:
            client.close()
    
    def getPossibleHosts(self, host_range=False, **kwargs):
        """
        Build a complete list of possible devices
        -range : Specifies the range selection mode for possible hosts
        -**kwargs : -start_range and -end_range
        """

        self.range_ip = self.local_IP.split(".")

        if self.prefix == '8':
            self.range_ip = ".".join(self.range_ip[0:1])
            self.range_ip += ".0.0.0"
        elif self.prefix == '16':
            self.range_ip = ".".join(self.range_ip[0:2])
            self.range_ip += ".0.0"
        elif self.prefix == '24':
            self.range_ip = ".".join(self.range_ip[0:3])
            self.range_ip += ".0"
        
        for ip in ipaddress.IPv4Network('{}/{}'.format(self.range_ip, self.prefix)):
            self.possible_hosts.append(str(ip))

        if host_range:
            start_range = kwargs["start_range"]
            end_range = kwargs["end_range"]
            self.possible_hosts = self.possible_hosts[start_range:end_range]


    def getMAC(self):
        """
        This function tries to find the MAC address of the device through IP
        """
        conf.verb = 0 # hide all verbose of scapy
        try:
            arp = ARP(pdst=self.IP)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            clients = []
            for sent, received in result:
                clients.append({"ip": received.psrc, "mac": received.hwsrc})
        except:
            self.mac = "Not Found"
        else:
            for client in clients:
                self.mac = client["mac"]
    
    def getMacManufacturer(self):
        """
        This function tries to identify the manufacturer information of the device through mac address
        """

        mac = MacLookup()

        try:
            mac.update_vendors()
        except:
            pass
        
        try:
            self.mac_manufacturer = mac.lookup(self.mac)
        except:
            self.mac_manufacturer = "Not Found"
        else:
            pass