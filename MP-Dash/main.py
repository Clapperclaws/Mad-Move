
import mp_dash as mp
import sys
import string
import subprocess
import signal
import datetime
#import pyshark
#import select
from sets import Set
import shlex
from tornado.gen import coroutine, Task, Return
from tornado.process import Subprocess
from tornado.ioloop import IOLoop
from datetime import datetime
from datetime import timedelta
from dateutil.parser import parse
from tornado.ioloop import PeriodicCallback
#https://stackoverflow.com/questions/40789824/is-there-any-way-to-change-callback-timeout-in-tornado-periodiccallback-instance

sys.path.insert(0, '/media/ubuntu/79bf333c-7b40-4765-9e0a-c16fa2b41163/muse/git/Mad-Move/data_analysis_scripts/')
from hw_predictor import hw_estimation
from hw_predictor import double_exponential_smoothing

#MP122-PRO:experiments_scripts ggrassi$  tshark  -r ~/Downloads/pcap_ondemand_4sec_8.16video.pcapng  -Y "http.response||http.request.method==GET" -Tfields -E separator=, -t e -e _ws.col.Time -e http.request.uri -e tcp.port -e ip.src  -e http.content_length -e http.request.uri -e http.request.line | grep 'ftp\|Range' | awk -F "=" '{if ($1==",Range: bytes") {print $2;} else {print $0}}' | awk -F "-" '{if (NF==2) {print $2-$1;} else {print $3;}}'

#log_directory = sys.argv[2]
#ping_log = open(log_directory+'/_log_'+str(log_directory)+'.txt', "w+")

VIDEO_PREFIX = "BigBuckBunny_4snonSeg.mp4"  ## if this changes, update MP_DASH_CHUNK_DURATION too!
#VIDEO_PREFIX = "Big"  ## if this changes, update MP_DASH_CHUNK_DURATION too!
MP_DASH_ALPHA = 0.1
MP_DASH_IS_BUFFER_BASED = True
MP_DASH_IS_RATE_BASED = False
MP_DASH_CHUNK_DURATION = 4

##network interfaces
LTEinterfaceName = "enp0s20u3u4"#sys.argv[1]
LTEinterfaceIP = "" #sys.argv[2] #enp0s20u3u2's IP
wifiInterfaceName = "wlo1"#sys.argv[3] #iwlo1
serverIP = "52.47.182.139" #sys.argv[4] #amazon server ip



#todo things to check
# wifi thgourhput
# overhead
#more?

global is_cell_on
global ltePcapParser
global wifiPcapParser
global current_mp_dash
global lteTimeOff
global lteLastTimeOn


global wifiRTT

is_cell_on = True
current_mp_dash = None

lteTimeOff = 0.0
lteLastTimeOn = 0.0
wifiRTT = timedelta(milliseconds=500)




class ThroughputEstimator:
    def __init__(self):
        self.pkts = []
        #self.throughputSeries = []
        self.throughput = 0.0
        self.rtt = 1
    #self.alpha = 0.8
    #self.beta = 0.2
    
    def updateRTT(self, rtt):
        self.rtt = rtt
    
    def addPkt(self, size, time):
        self.pkts.insert(0, ((size, time)))
        self.updateThroughput(self.rtt, time)
    
    def updateThroughput(self, rtt, time):
        cleanList = []
        data = 0.0
        self.rtt = rtt
        for el in self.pkts:
            if  el[1] >time-rtt:
                cleanList.append(el)
                data+=el[0]
            else:
                break #array is sorted. we can remove the rest
        
        self.pkts = cleanList
	if data <= 0 :
		return #todo to moving average too
        self.throughput = data/rtt
#self.throughputSeries.append(self.throughput)



class HoltThroughputEstimator:
    def __init__(self):
        self.pkts = []
        self.throughputSeries = []
        self.throughput = 0.0
        self.rtt = -1.0
        self.alpha = 0.8
        self.beta = 0.2
        self.nextUpdate = -1
        self.trend = 0.0
        self.level = 0.0
    
    def updateRTT(self, rtt):
	print "NEW RTT " + repr(rtt)
        self.rtt = rtt
    
    
    def addPkt(self, size, time):
        self.pkts.insert(0, ((size, time)))
    	print "Adding HoltThroughputEstimator pkt " + repr(size) + " " + str(time) + " " + str(len(self.pkts))
    
    def updateThroughput(self):
        global wifiRTT
        data = 0.0
        for el in self.pkts:
            data+=el[0]
        self.throughput = data/(wifiRTT.microseconds/1000000.0)
        self.throughputSeries.append(self.throughput)
        print "update THROUGHPUT " + repr(data) + " " + repr(wifiRTT.microseconds)+  " " + repr(self.throughput)
        if self.rtt!=-1:
            wifiRTT = timedelta(milliseconds=self.rtt*1000.0)
            print "RTT " + str(wifiRTT)
        del self.pkts [:]
    
    def getHoltPrediction(self):
        if len(self.throughputSeries)==0 :
            return 0


	#for el in self.throughputSeries:
	#	print "THROUGHPUT " + repr(el)
	print "old holt " + repr(double_exponential_smoothing(self.throughputSeries,self.alpha, self.beta)[len(double_exponential_smoothing(self.throughputSeries,self.alpha, self.beta))-1])
        estimate, self.level, self.trend = hw_estimation(self.throughputSeries, self.level, self.trend, self.alpha, self.beta)
	print "HOLT " + repr(estimate) + " level" + repr(self.level) + " trend " + repr(self.trend)
        return estimate


class HTTPChunk:
    def __init__(self, uri, port, bitrate):
        self.uri = uri
        self.rangeStart = -1
        self.rangeEnd = -1
        self.port = port
        self.bitrate = bitrate
	self.isComplete = False

class Packet:
    def __init__(self, time, sourceInterface, sourcePort, size, rtt,isIncoming):
        self.sourceInterface = sourceInterface
        self.sourcePort = sourcePort
        self.size = size
        self.rtt = rtt
        self.isIncoming = isIncoming
        self.time = time


class TsharkOutput:
    def __init__(self, packet, httpReq):
        self.packet = packet
        self.httpReq = httpReq

class tsharkParser:
    
    def __init__(self, name, throughputEstimator):
        self.httpGetInProgress = False
        self.name = name
        self.inProgressGet = None
        self.inProgressPkt = None
        self.throughputEstimator = throughputEstimator
    
    
    
    #mp_dash.on_packet_received(result.packet.time,10XXX00,result.packet.size,is_cell_on) #some random values
    
    
    def parsePcapMessage(self, fd, event):
        content = fd.readline()
        messageArray = content.split(',')
	#print "parsePcapMessage " + str(content)        	
        if self.httpGetInProgress==False:
            if len(messageArray)<5:
                return None ##it's the last part of http request
        
            self.inProgressGet=None
            timestamp = float(messageArray[0])
            
            requestUri = messageArray[7]
            size = int(messageArray[6])
            rtt =  float(messageArray[5]) if len(messageArray[5])>0 else -1
            port = int(messageArray[2])
            
            isIncoming = (port!=8080)
           # print "pkt !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! " + str(content)
            isHttpGet = (content.find(VIDEO_PREFIX)!=-1)
            
            self.inProgressPkt = Packet(timestamp, self.name, port, size, rtt, isIncoming)
            if isHttpGet:
                self.httpGetInProgress = True ## it's a http get reqeust, the next new lines will be the request details
		print "HTTP GET debug" + str(content)               
			#print "HTTP self.httpGetInProgress " + content
                bitrate = int((requestUri.split('_')[1]).split('b')[0])
                self.inProgressGet = HTTPChunk(requestUri, port, bitrate)  ##we cannot return this iuntil is complete!!!!! todo
                
                return None ##we will return the final data when the http parsing is done
	elif content.find("Range")!=-1:
                #print "RangeRangeRangeRangeRangeRange " + str(messageArray[0])
                #print content
                rangeStr = messageArray[1][13:]
                self.inProgressGet.rangeStart = int(rangeStr.split('-')[0])
                self.inProgressGet.rangeEnd = int(rangeStr.split('-')[1])
                self.httpGetInProgress = False
		self.inProgressGet.isComplete=True
    #print "RANGES " + str(self.inProgressGet.rangeStart) + " " + str(self.inProgressGet.rangeEnd)+ " " + str(self.inProgressGet.uri)
    
	else:
		print "pkt jttp in prgress no range " + str(content)
        return TsharkOutput(self.inProgressPkt, self.inProgressGet)


##todo get payload (might not be tcp payload if the respose carries data)
## keep tracks of PORT number;





turnOffCommand = ("sudo ip link set dev " + LTEinterfaceName + " multipath off").split()
turnONCommand = ("sudo ip link set dev " + LTEinterfaceName + " multipath on").split()
turnBackupCommand = ("	 " + LTEinterfaceName + " multipath backup").split()


def getMillisecondsNow():
	now =  datetime.now()
	epoch=parse('1970-01-01T00:00:00')
        td = now - epoch
        return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6


def rttExpired():
    global wifiRTT
    print "rttExpired " + repr(wifiRTT)
    wifiPcapParser.throughputEstimator.updateThroughput()
    IOLoop.instance().add_timeout(wifiRTT, rttExpired)



def run_command(command):
    print "Running command " + str(command)
    p = subprocess.Popen(['stdbuf', '-o0']+command,#shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
                         #, universal_newlines=True, bufsize=1)
    return p



def disableLTE():
    global lteTimeOff
    global lteLastTimeOn
    
    run_command(turnOffCommand)  ###todo turning off or putting it in backup mode??
    lteLastTimeOn =  getMillisecondsNow() #datetime.now().time()


def enableLTE():
    global lteTimeOff
    global lteLastTimeOn
    run_command(turnONCommand)
    lteTimeOff += (getMillisecondsNow() -lteLastTimeOn)
    lteLastTimeOn = 0.0


def onDataLTE(fd, event):
    result = TsharkOutput(None,None)
    result = ltePcapParser.parsePcapMessage(fd, event)

    if result ==None:
	return	
    if result.httpReq!=None:
	if result.httpReq.isComplete==False:
		return
 
    handlePkt(result, ltePcapParser.throughputEstimator, wifiPcapParser.throughputEstimator, ltePcapParser.throughputEstimator)

def onDataWiFi(fd, event):
    result = TsharkOutput(None,None)
    result = wifiPcapParser.parsePcapMessage(fd, event)
    if result ==None:
	return
    if result.httpReq!=None:
	if result.httpReq.isComplete==False:
		return
    handlePkt(result, wifiPcapParser.throughputEstimator, wifiPcapParser.throughputEstimator, ltePcapParser.throughputEstimator)

def resetLTEStatus():
    global lteTimeOff
    global lteLastTimeOn
    global is_cell_on
    lteTimeOff = 0.0
    lteLastTimeOn = 0.0 if is_cell_on else getMillisecondsNow()

def handlePkt(result, throughputEstimator, wifiThroughputEstimator, LTEThroughputEstimator ): ##throughputEstimator is either wifiThroughputEstimator or LTEThroughputEstimator, depending on the caller. it's a quick fix to have everything we neeed for mp_dash
    global current_mp_dash
    global is_cell_on
    global lteTimeOff
    
    
    if result!=None:
        #print "PKT " + result.packet.sourceInterface + " " + str(result.packet.size) + " " + str(result.packet.rtt) + " isIncoming " +  str(result.packet.isIncoming)
        if result.httpReq!=None:
            print "HTTP GET " + result.httpReq.uri + " " + str(result.httpReq.rangeStart) + " " + str(result.httpReq.rangeEnd)
            resetLTEStatus()
            if result.httpReq.rangeEnd > 2800:
                if current_mp_dash != None:
                    print "new MPDASH"
		    current_mp_dash.close_websocket()
                #print "BITRATE " + str(result.httpReq.bitrate)
                current_mp_dash = mp.mp_dash(result.packet.time,result.httpReq.rangeEnd - result.httpReq.rangeStart,result.httpReq.bitrate, MP_DASH_ALPHA, MP_DASH_CHUNK_DURATION, MP_DASH_IS_RATE_BASED, MP_DASH_IS_BUFFER_BASED)
		print "mp_dash " + str(current_mp_dash)
    
        if result.packet.isIncoming==True:
            if result.packet.rtt>0:
                throughputEstimator.updateRTT(result.packet.rtt)
                #print "RTT in Incoming " + str(result.packet.rtt) + " " + str(throughputEstimator.throughput)
            
            throughputEstimator.addPkt(result.packet.size, result.packet.time)
            #print "NEW UPDATE   " + str(throughputEstimator.throughput) + " " + repr(result.packet.time) + " " + str(throughputEstimator.rtt) + " till " + repr(result.packet.time-throughputEstimator.rtt) + " size " + repr(result.packet.size)
            if current_mp_dash != None:
                #print "New pkt wifi" + repr(wifiThroughputEstimator.getHoltPrediction()) + " LTE " + repr(LTEThroughputEstimator.throughput)
                
                shouldLteBeOff = current_mp_dash.on_packet_received(result.packet.time, result.packet.size, wifiThroughputEstimator.getHoltPrediction(), LTEThroughputEstimator.throughput,  lteTimeOff)
                
                if is_cell_on == True and shouldLteBeOff==0:
                    print "disableLTE()"
                    disableLTE()
                    is_cell_on = False
                elif is_cell_on == False and shouldLteBeOff==1:
                    print "enableLTE()"
                    enableLTE()
                    is_cell_on = True
            else:
                print "WARNING we have a new tcp pkt, but no mpdash object"


LTEmonitor_command = ("sudo tshark -l -i " + LTEinterfaceName  + " -Y ").split()
#LTEmonitor_command = (" tshark -l -r pcap_dash_153390783.pcap -Y ").split()
#                      ../pcap_ondemand_4sec_8.16video.pcapng -Y ").split()
#todo check if by using tcp.srcport == 8080 we still get rtt info tcp.srcport==8080 &&
#cmd = "(ip.dst == " +str(serverIP) + " || ip.src == " +str(serverIP)+") && ((tcp &&  !tcp.analysis.retransmission) || (http.request.method==\"GET\"  && ip.dst == " +str(serverIP)+"))"

cmd = "(ip.dst == " +str(serverIP) + " || ip.src == " +str(serverIP)+") && ((tcp) || (http.request.method==\"GET\"  && ip.dst == " +str(serverIP)+"))"


LTEmonitor_command.append(cmd)
for el in ("-Tfields -E separator=, -t e -e _ws.col.Time -e tcp.port -e ip.src  -e http.content_length -e tcp.analysis.ack_rtt -e tcp.len -e http.request.uri -e http.request.line").split():
    LTEmonitor_command.append(el)


Wifimonitor_command = ("sudo tshark -l -i " + wifiInterfaceName  + " -Y ").split()
#Wifimonitor_command = (" tshark -l -r in_lab/sept_17_2018/dash_4s/1537192189/wifi_1537192189.pcap").split() # -Y ").split()
#cmd = "(ip.dst == " +str(serverIP) + " || ip.src == " +str(serverIP)+") && ((tcp &&  !tcp.analysis.retransmission) || (http.request.method==\"GET\"  && ip.dst == " +str(serverIP)+"))"

cmd = "(ip.dst == " +str(serverIP) + " || ip.src == " +str(serverIP)+") && ((tcp) || (http.request.method==\"GET\"  && ip.dst == " +str(serverIP)+"))"

Wifimonitor_command.append(cmd)
for el in ("-Tfields -E separator=, -t e -e _ws.col.Time -e tcp.port -e ip.src  -e http.content_length -e tcp.analysis.ack_rtt -e tcp.len -e http.request.uri -e http.request.line").split():
    Wifimonitor_command.append(el)


#avoiding retransmission
#tcp.analysis.fast_retransmission
#tcp.analysis.retransmission
#tcp.analysis.spurious_retransmission


#processes
LTEmonitor_process = run_command(LTEmonitor_command)
Wifimonitor_process = run_command(Wifimonitor_command)



ltePcapParser = tsharkParser("LTE", ThroughputEstimator())
wifiPcapParser = tsharkParser("WiFi", HoltThroughputEstimator())

IOLoop.instance().add_handler(LTEmonitor_process.stdout, onDataLTE , IOLoop.READ) #/*ltePcapParser.pcapOnData*/
IOLoop.instance().add_handler(Wifimonitor_process.stdout, onDataWiFi, IOLoop.READ)



IOLoop.instance().add_timeout(wifiRTT, rttExpired)

IOLoop.instance().start()
