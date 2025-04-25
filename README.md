
![localmapscreenshot](https://user-images.githubusercontent.com/128434167/229271973-7ba89b37-4bcb-439c-ab6b-a1b2cfb9de6a.png)

> ⚠️ **Important:**  
> At the time I was working on this project, my main goal was to get it running on my own machine. It hasn't been optimized for other environments, so you may run into issues.

localmap is a security tool for scanning the local network This tool can find all active hosts in a network and their specifications such as name - Open ports - MAC address - Mac manufacturer and Operating system.

localmap can perform a full TCP port scan for any active host in the network and determine the active services on each port. This tool displays the active operating system on each host by checking the fingerprints of packets received from each host and each port.






## Screenshot
![Localmap](https://user-images.githubusercontent.com/128434167/229272012-e59fce87-cb72-4582-95c8-caafe7963219.png)






## Installation
Clone of this repository: 

---
    git clone https://github.com/MatinAfzal/Localmap
---



## Usage

Open cmd with administrator access level:
```
C:\Windows\system32> cd ./<path>/LOCAL MAP

C:\LOCAL MAP> python localmap.py

```




## Requirements
Python 3.10.7 > ---> https://www.python.org/downloads/  
mac_vendor_lookup library ---> https://pypi.org/project/mac-vendor-lookup/  
scapy library ---> https://pypi.org/project/scapy/  
tqdm library ---> https://pypi.org/project/tqdm/  
colorama library ---> https://pypi.org/project/colorama/  
npcap ---> https://npcap.com/#download  

## Attention
This tool has been tested on Windows and works well with high speed. This tool is also optimized for Linux, however it (might) run into issues on Linux!

## Disclaimer
localmap is a security tool for scanning local networks. Using this tool outside of the test environment can cause damage to the network and can have legal consequences for the user. The consequences of any unethical or illegal use are entirely the responsibility of the user. Also, any possible damage to the network is the responsibility of the user.


## Authors
- Created by Matin Afzal
- E-mail: contact.matin@yahoo.com
- Github: [@MatinAfzal](https://www.github.com/MatinAfzal)

