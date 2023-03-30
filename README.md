# Localmap
localmap is a security tool for scanning the local network This tool can find all active hosts in a network and their specifications such as name - Open ports - MAC address - Mac manufacturer and Operating system.

localmap can perform a full TCP port scan for any active host in the network and determine the active services on each port.
This tool displays the active operating system on each host by checking the fingerprints of packets received from each host and each port.

![Localmap](https://user-images.githubusercontent.com/128434167/228738033-374fb4d5-3e93-4566-9e8b-4bbd4258f45f.png)

# Disclaimer
localmap is a security tool for scanning local networks. Using this tool outside of the test environment can cause damage to the network and can have legal consequences for the user.
The consequences of any unethical or illegal use are entirely the responsibility of the user.
Also, any possible damage to the network is the responsibility of the user.

# Attention
This tool has been tested on Windows and works well with high speed. This tool is also optimized for Linux, however it (might) run into issues on Linux!

# Requirements
Python 3 >  
mac_vendor_lookup library ---> https://pypi.org/project/mac-vendor-lookup/   
scapy library ---> https://pypi.org/project/scapy/  
tqdm library ---> https://pypi.org/project/tqdm/  
colorama library ---> https://pypi.org/project/colorama/  
npcap ---> https://npcap.com/#download  
	
# Usage
Open cmd with administrator access level:

	C:\Windows\system32> cd ./<path>/LOCAL MAP
	
	C:\LOCAL MAP> python localmap.py
  
  # Created by
  	    Matin Afzal
        Github: https://github.com/MatinAfzal
        E-mail: contact.matin@yahoo.com
