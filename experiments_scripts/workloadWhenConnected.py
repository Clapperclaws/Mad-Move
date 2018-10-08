import sys
import string
import subprocess
import signal
import datetime


from time import sleep

#arguments: timestamps used to identify file and directory; redirect output of the script if interested in getting logs about getting/losing ip address


def run_command(command):
    print "COMMAND " + str(command)
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return p



def has_new_address(minotorOutput):
#    @if minotorOutput.find("ROUTE")!=-1:
 #       if minotorOutput.find("default") !=-1 and minotorOutput.find("Deleted")==-1:
  #          return True
    if minotorOutput.find("ADDR")!=-1:
        if minotorOutput.find("scope") !=-1 and minotorOutput.find("global")!=-1 and minotorOutput.find("Deleted")==-1:
            return True

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
    if ping_process != None:
        ping_process.kill()
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
#workload_command = 'wget -c http://35.180.114.57:8080/download/ubuntu.iso'.split()

workload_command = 'google-chrome --incognito --user-data-dir=/tmp/chrome-profile --no-proxy-server --enable-quic --origin-to-force-quic-on=www.example.org:443'.split()
workload_command.append('--host-resolver-rules=MAP www.example.org:443 35.180.114.57:6121')
workload_command.append('https://www.example.org/bigfile.txt') #.split()




#workload_command = 'wget -c http://releases.ubuntu.com/18.04.1/ubuntu-18.04.1-desktop-amd64.iso?_ga=2.121902795.1377299371.1533299868-476592716.1533299868'.split()

ping_command = 'ping -i 0.2 8.8.8.8 -D'


### logs
log_directory = sys.argv[1]
ping_log = open(log_directory+'/ping_log_'+str(log_directory)+'.txt', "w+")


### process
ping_process = None
monitor_process = run_command(monitor_command)
workload_process = None


for line in iter(monitor_process.stdout.readline, b''):
    print(line)
    sys.stdout.flush()
#    monitor_process.kill()
    if has_new_address(line)==True:
        print("MAD-MOVE: new address " + line)
        sys.stdout.flush()
        if workload_process!= None:
            #todo should we kill it??
            print str(datetime.datetime.now()) + " killing and starting again the workload, it was already running"
            workload_process.kill()
        workload_process = run_command(workload_command)
        if ping_process == None:
            #first time we have connectivity, we can start ping (it should stay up if we lose connectivity)
            ping_process = subprocess.Popen(ping_command, shell=True, universal_newlines=True, stdout=ping_log)
    elif did_lose_address(line) == True:
        print("MAD-MOVE: lost address " + line)
        sys.stdout.flush()
        if workload_process != None:
            workload_process.kill()
            workload_process = None


