import sys
import string
import subprocess
import signal
import datetime
#import pyshark
import select
from sets import Set


#log_directory = sys.argv[2]
#ping_log = open(log_directory+'/_log_'+str(log_directory)+'.txt', "w+")

interfaceName = sys.argv[1] #enp0s20u3u2 (or file: -F at the end is needed)
interfaceIP = sys.argv[2] #enp0s20u3u2's IP
wifiInterfaceName = sys.argv[3] #iwlo1

##settings
mptcpDuplicateAckThreshold = 5


fromFile = False
if len(sys.argv) > 4:
    fromFile = sys.argv[4].find("-F")!=-1




def run_command(command):
    print "Running command " + str(command)
    p = subprocess.Popen(['stdbuf', '-o0']+command,#shell=True,
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.STDOUT)#, universal_newlines=True, bufsize=1)
    return p

source="-i " + interfaceName
rawSource = "-i fish0"
rawSource = "-r ../../../MPTCP_test/in_lab/1535013679/monitor.pcap" #-i fish0"
if fromFile:
    source = "-r " + interfaceName




##commands
monitor_command = ("sudo tshark -l " + source  + " -Y ").split()
monitor_command.append("ip.src == " + str(interfaceIP)+ " && tcp.options.mptcp.dataackpresent.flag == 1 &&  !tcp.analysis.duplicate_ack")
for el in ("-Tfields -t e -e _ws.col.Time -e tcp.options.mptcp.rawdataack").split():
    monitor_command.append(el)	


turnOffCommand = ("sudo ip link set dev " + wifiInterfaceName + " multipath off").split() 


#todo
rawMonitorCommand = ("sudo tshark " + rawSource + " -Y ").split()
rawMonitorCommand.append("wlan.da == 64:80:99:8c:61:a8 && wlan.fc.type == 2")
for el in (" -Tfields -t e -e _ws.col.Time -e radiotap.datarate -e wlan.fc.retry").split():
    rawMonitorCommand.append(el)	



#processes
monitor_process = run_command(monitor_command)
raw_monitor_process = run_command(rawMonitorCommand)







inputs = [monitor_process.stdout, raw_monitor_process.stdout]




## offline
bitrates = {}
duplicatesSession = []
pkts = {}


##MPTCP 
lastMPTCPAck = -1
mptcpDuplicateAckCounter = 0
lastTime = -1.0
duplicateAckStartSession = -1.0


debugCounter =0
keepGoing = True
while keepGoing:
	readable, writable, exceptional = select.select(inputs, [], inputs)


	for s in readable:
            if s is monitor_process.stdout:  ### LTE MPTCP MONITOR
		    line = s.readline()
		    debugCounter+=1
   		    if debugCounter>210000:
			keepGoing=False

		    if line.find("Running")!=-1 or line.find("shark")!=-1 :
			continue
		    ack = int(line.split()[1])
		    timestamp = float(line.split()[0])

		    if lastMPTCPAck==ack:

			mptcpDuplicateAckCounter+=1
			if duplicateAckStartSession==0:
			    duplicateAckStartSession=timestamp

		    else:
			if mptcpDuplicateAckCounter > mptcpDuplicateAckThreshold:
			     print "MPTCP DUPLICATE ACKs " + str(mptcpDuplicateAckCounter) + " from " + str(duplicateAckStartSession) + " to " + str(lastTime) + " " + str(lastMPTCPAck)
			     duplicatesSession.append([duplicateAckStartSession, lastTime, mptcpDuplicateAckCounter])
		    
			duplicateAckStartSession = 0
			mptcpDuplicateAckCounter=0

		    lastMPTCPAck = ack
		    lastTime = timestamp
		    sys.stdout.flush()
	    elif s is raw_monitor_process.stdout:   
		line = s.readline()	
		if not line:
			#s.close()
	#		keepGoing=False
			break

 	    	if line.find("Running")!=-1 or line.find("shark")!=-1 :
			continue
		
		#print "raw_monitor_process " + str(line)
   	        timestamp = int(line.split()[0].split('.')[0])
   	        rate = int(line.split()[1].split(',')[0])

		if bitrates.has_key(timestamp)==False:
			bitrates[timestamp] = Set()
		bitrates[timestamp].add(rate)

		if pkts.has_key(timestamp)==False:
			pkts[timestamp] = {}
			pkts[timestamp]['rx'] = 0
			pkts[timestamp]['retx'] = 0

		if len(line.split())>2:
			retx = int(line.split()[2])
			if retx == 1:
				pkts[timestamp]['retx'] = pkts[timestamp]['retx'] +1	
			pkts[timestamp]['rx'] = pkts[timestamp]['rx'] +1	

	for s in exceptional:
		print "exceptional" 
		s.close()

for session in duplicatesSession:
	print str(session)
	if bitrates.has_key(int(session[0])):
		for el in bitrates[int(session[0])]:
			print str(el)
	else:
		print "NO RATES"


	if pkts.has_key(int(session[0])):
		print "PKTS " + str(pkts[int(session[0])]['rx']) + " " + str(pkts[int(session[0])]['retx'])
	else:
		print "PKTS"

