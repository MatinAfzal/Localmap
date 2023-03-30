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
# F: isPackageInstalled():  Checks if a package is installed or not.
# F: packageListCheck(): Checks if a list of packages is installed or not
# (by calling is PackageInstalled() function)
# F: macLookupTest(): It seems that mac_vendor_lookup package is installed
# but it is facing problems on Linux (Test Function)
############################################################################

import subprocess
import mac_vendor_lookup
from colorama import init, Fore

# File identity information
__author__ = 'Matin Afzal (contact.matin@yahoo.com)'
__version__ = '0.0.1'
__last_modification__ = '2023/03/29'

# Assigning coloroma colors
init()
RED = Fore.RED
RESET = Fore.RESET

def isPackageInstalled(package_name):
    """
    Single package install check
    +returns 0 = Yes / 1 = No / False = Error
    """
    try:
        return subprocess.call(["pip", "show", package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def packageListCheck(package_list):
    """
    List of packages install check
    + if installed pass / else: exit()
    """
    for package in package_list:
        is_installed = isPackageInstalled(package)

        if is_installed:
            pass
        else:
            print(f"{RED}[Error]{RESET}:{package} is NOT installed.")
            print(f"Try to install the required package with pip install {package} command")
            exit()
    macLookupTest()

def macLookupTest():
    try:
        test = mac_vendor_lookup.MacLookup()
    except:
        print(f"{RED}[Error]{RESET}: mac_vendor_lookup package is NOT working.")
    else:
        pass