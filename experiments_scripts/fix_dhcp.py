import sys
import string
import subprocess
import signal
import datetime


from time import sleep

#arguments: timestamps used to identify file and directory; redirect output of the script if interested in getting logs about getting/losing ip address


DHCP4_IP_ADDRESS=""
IP4_ADDRESS_0=""			
DHCP4_NETWORK_NUMBER="192.168.243.0"  #default.. Free the first time doesn't tell us anything about it
DHCP4_ROUTERS=""
CLEANED = False

IsInLab = False

####wifi in lab
#DHCP4_IP_ADDRESS=""
#IP4_ADDRESS_0=""			
#DHCP4_NETWORK_NUMBER="192.168.243.0"  #default.. Free the first time doesn't tell us anything about it
#DHCP4_ROUTERS=""
#CLEANED = False

def run_command(command):
    print "Running command " + str(command)
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return p


def checkIfComplete():
    global DHCP4_IP_ADDRESS
    global IP4_ADDRESS_0
    global DHCP4_NETWORK_NUMBER
    global DHCP4_ROUTERS
    global CLEANED
    return len(DHCP4_IP_ADDRESS)>1 and len(IP4_ADDRESS_0)>1 and len(DHCP4_NETWORK_NUMBER)>1 and len(DHCP4_ROUTERS)>1

def clearInfo():
    global DHCP4_IP_ADDRESS
    global IP4_ADDRESS_0
    global DHCP4_NETWORK_NUMBER
    global DHCP4_ROUTERS
    global CLEANED
    print "Cleaning"	
    if CLEANED==False:
	run_command(("sudo /home/ubuntu/Desktop/mptcp_down").split())
    DHCP4_IP_ADDRESS=""
    IP4_ADDRESS_0=""			
    #DHCP4_NETWORK_NUMBER=""
    DHCP4_ROUTERS=""
    CLEANED = True

def has_new_address(minotorOutput):
#    @if minotorOutput.find("ROUTE")!=-1:
 #       if minotorOutput.find("default") !=-1 and minotorOutput.find("Deleted")==-1:
  #          return True
    global DHCP4_IP_ADDRESS
    global IP4_ADDRESS_0
    global DHCP4_NETWORK_NUMBER
    global DHCP4_ROUTERS
    global CLEANED
    global IsInLab
    if minotorOutput.find("ADDR")!=-1:
        if minotorOutput.find("scope") !=-1 and minotorOutput.find("global")!=-1 and minotorOutput.find("Deleted")==-1:
	    full_ip = minotorOutput.split()[4]
	    if full_ip.find("inet")!=-1:
	        full_ip = minotorOutput.split()[5]
	    DHCP4_IP_ADDRESS = full_ip.split('/')[0]
	    IP4_ADDRESS_0=full_ip
	    print "Setting DHCP4_IP_ADDRESS " + str(DHCP4_IP_ADDRESS) + " IP4_ADDRESS_0 " + IP4_ADDRESS_0
	    CLEANED = False
	    return IsInLab or checkIfComplete()

#[2018-09-12T16:16:33.311015] [ADDR]3: wlo1    inet 192.168.1.228/24 brd 192.168.1.255 scope global dynamic wlo1


    elif minotorOutput.find("ROUTE")!=-1:
	if minotorOutput.find("proto dhcp scope link") !=-1:
    	    DHCP4_ROUTERS = minotorOutput.split()[1].split(']')[1]
	    IP4_ADDRESS_0 += ";"
	    IP4_ADDRESS_0 += DHCP4_ROUTERS ##todo check if it is always true
	    print "setting DHCP4_ROUTERS " + DHCP4_ROUTERS + " IP4_ADDRESS_0 " + IP4_ADDRESS_0
	    CLEANED = False
	    return IsInLab or checkIfComplete()
	elif minotorOutput.find("broadcast") !=-1:	
 	    ip = minotorOutput.split()[2]
	    if ip.find('.0')!=-1:
  	        DHCP4_NETWORK_NUMBER=ip
	        print "Setting DHCP4_NETWORK_NUMBER " + DHCP4_NETWORK_NUMBER 
    	        CLEANED = False
	    	return IsInLab or checkIfComplete()

#2018-08-06T15:09:56.677990] [ADDR]3: wlo1    inet 192.168.243.128/24 brd 192.168.243.255 scope global dynamic wlo1
#       valid_lft 7200sec preferred_lft 7200sec


# [ROUTE] 192.168.243.2 proto dhcp scope link src 192.168.243.128 metric 1024 

#(OLD)[2018-08-06T15:09:53.455498] [ROUTE]broadcast 192.168.243.0 table local proto kernel scope link src 192.168.243.128 linkdown 


#DHCP4_IP_ADDRESS="192.168.243.128"    <- inet without / **<****
#IP4_ADDRESS_0="192.168.243.128/24 192.168.243.2"   inet with /24 + ROUTE  ******			
#DHCP4_NETWORK_NUMBER="192.168.243.0"   	?? [ROUTE]broadcast 
#DHCP4_ROUTERS="192.168.243.2" 	??  SAME AS ROUTE??		****


##triggeref
#[2018-08-06T15:16:07.215114] [NEIGH]192.168.243.2 lladdr 70:4f:57:8f:10:e3 STALE
#[2018-08-06T15:16:08.859766] [ROUTE]192.168.243.0/24 table wlo1 scope link 
#[2018-08-06T15:16:08.860442] [ROUTE]default via 192.168.243.2 table wlo1 
#[2018-08-06T15:16:08.861201] [RULE]32763:	from 192.168.243.128 lookup wlo1 



    return False

def did_lose_address(minotorOutput):
    #todo return true if monitorOutput says we lost the ip address
    if minotorOutput.find("ROUTE")!=-1:
        if minotorOutput.find("default") !=-1 and minotorOutput.find("Deleted")!=-1:
            return True
    if minotorOutput.find("LINK")!=-1:
        if minotorOutput.find("DOWN") !=-1:
            return True


    return False

def sigterm_handler(_signo, _stack_frame):
    # Raises SystemExit(0):
    print "killing everything"
    #if ping_process != None:
    #   ping_process.kill()
    if workload_process != None:
        workload_process.kill()
    monitor_process.kill()

    sys.exit(0)


#gracefull exit
signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

###commands
monitor_command = 'ip -ts monitor label dev wlo1'.split()  #todo by specifying "route" we limit the useless messages (at the moment better to keep everything, just in case)

#monitor_command = 'ls'.split()


monitor_process = run_command(monitor_command)

clearInfo()

for line in iter(monitor_process.stdout.readline, b''):
    print(line)
    sys.stdout.flush()
#    monitor_process.kill()
    if has_new_address(line)==True:
        print("MAD-MOVE: new address " + "DHCP4_IP_ADDRESS " + DHCP4_IP_ADDRESS + " IP4_ADDRESS_0 " + IP4_ADDRESS_0 + " DHCP4_NETWORK_NUMBER " + DHCP4_NETWORK_NUMBER + " DHCP4_ROUTERS " + DHCP4_ROUTERS + " " + line)	
	if IsInLab == True:	
    	    run_command(("sudo /home/ubuntu/Desktop/mptcp_up ").split() )
	else:
            run_command(("sudo /home/ubuntu/Desktop/mptcp_up " + DHCP4_IP_ADDRESS + " \"" + IP4_ADDRESS_0 + "\" " + DHCP4_NETWORK_NUMBER + " " + DHCP4_ROUTERS).split() )
        sys.stdout.flush()
    elif did_lose_address(line) == True:
        print("MAD-MOVE: lost address " + line)
	clearInfo()
        sys.stdout.flush()


