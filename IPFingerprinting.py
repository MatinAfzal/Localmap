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
# F: OSFingerprint(): This function tries to guess the target operating
# system by listening and checking the response packets received from the
# target IP and using pyp0f detects the target operating system.
# F: from_hex(): 
############################################################################

import socket
import binascii
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import IP as IPv4
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_tcp
from pyp0f.fingerprint.tcp import valid_for_fingerprint
from pyp0f.net.packet import Packet, parse_packet
from pyp0f import *

# File identity information
__author__ = 'Matin Afzal (contact.matin@yahoo.com)'
__version__ = '0.0.3'
__last_modification__ = '2023/03/27'

def OSFingerprint(target_IP, target_ports):
    """
    This function detects the target IP operating system
    -target_IP : target IP
    -target_port : target port
    +returns : OS_info
    """

    for target_port in target_ports:
        conf.verb = 0 # hide all verbose of scapy

        target_port = int(target_port)

        # Class assignment
        ip = IP(dst=target_IP)
        syn = TCP(sport=1234, dport=target_port, flags='S', seq=12345)

        # Create Socket (Class assignment)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # SYN Packet Sending
        response = sr1(ip/syn, verbose=0)
        original_packet = response[0]

        # Check the answer
        if response.haslayer(TCP) and response[TCP].flags & 0x12:
            temp_packet = hexdump(original_packet, dump=True)
            
            # adding extra '\n' to the end of temp_packet
            temp_packet += '\n'

            # Variables needed to make a proper packet to send to pyp0f
            packet_lines = []
            Illegal_spaces = ['.']
            Illegal_characters = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            temp_line = ''
            temp_line_list = []

            for character in temp_packet:
                if (character not in Illegal_spaces) and (character not in Illegal_characters):
                    temp_line += character

                    if character == '\n':
                        # packet_lines.append(temp_line)
                        tempVariable = temp_line.split(' ')
                        temp_line_list.append(tempVariable)

                        tempVariable = ''
                        temp_line = ''
            
            for line in temp_line_list:
                line = line[2:]
                for character in line:
                    temp_line += character
                    
                    if character == '':
                        break
            
            DATABASE.load()

            pyp0f_packet = from_hex(temp_line)

            try:
                if valid_for_fingerprint(pyp0f_packet):
                    tcp_result = fingerprint_tcp(pyp0f_packet)
                    os_fingerprint = tcp_result.match.record.label.dump()
            except:
                pass
            else:
                if os_fingerprint != None:
                    return os_fingerprint

def from_hex(packet: str, ip_version: int = 4) -> Packet:
    ip_cls = IPv4 if ip_version == 4 else IPv6
    return parse_packet(ip_cls(binascii.unhexlify(packet)))