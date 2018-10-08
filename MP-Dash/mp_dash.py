from websocket import create_connection

class mp_dash:

    '''MP-DASH is initialize with:
      Start-time -- indicates the time the HTTP Request is sent
      Chunk-size -- indicates the size of the chunk in Bytes
      Bit-rate   -- indicates the chunk bitrate (quality)
      Alfa -- to compensate for estimation inaccuracy
      Chunk-duration -- indicates the size of a chunk in seconds of video
      a boolean is-rate-based to distinguish between rate-based or duration-based Deadline estimation methods
      a boolean is-buffer-based to set the omega & phi according to the ABR algorithm
    '''
    def __init__(self, start_time, chunk_size, bit_rate, alfa, chunk_duration, is_rate_based, is_buffer_based):

        self.chunk_size = chunk_size # Synonymous to S - video chunk size
        self.sent_bytes = 0 # Total amount of bytes sent so far
        self.start_time = start_time # Time when HTTP Get request is sent
        self.alfa = alfa # Alfa is used to compensate the estimation inaccuracy of Wifi Throughput
        self.mode = is_rate_based # This mode indicates if the deadline is set as rate-based or duration-based
        #self.packet_size = 1500
	
	#set the deadline
        if(is_rate_based):
            self.deadline_window = float(chunk_size * 8)/float(bit_rate)
        else:
            self.deadline_window = chunk_duration

	#set Omega & Phi based on ABR algorithm type
        if(is_buffer_based):
            self.phi = 56 #Total buffer capacity (60) - segment-size (4)
            self.omega = 12 #Buffer-length that maps to the lowest bitrate (reservoir = 5 sec) + segment-size
        else:
            self.phi = 48 #80% of total buffer-capacity
            self.omega = 32 # Minimum set to be 40% of buffer-capacity
	
	#Start a connection to the websocket server
	self.ws = create_connection("ws://localhost:9001")

	# Request Buffer Level from DASH Client
        self.ws.send("buffer_request")
	print "Asking for buffer level"
        # Read Reply from Server
        result = self.ws.recv()
	print result
        # This stripping & trimming is to handle the javascript output function -- could be modified
        self.buffer_level = float(str.strip(result.split(':')[2]))
	print "Buffer level",self.buffer_level
        
        # Adjust the deadline window
        self.D = self.deadline_window
        if self.buffer_level > self.phi:
            self.D =self.buffer_level + (self.buffer_level - self.phi)


    #This function closes the websocket
    def close_websocket(self):
	self.ws.close()    
    
    # MP-DASH function to enable/disable cellular sub-flow -- assumes as input, timenow, wifi-throughput,
    # amount of sent-bytes, boolean if Cellular subflow is enabled/disabled
    # This function return 0 to disable the cellular path and 1 to enable the cellular path
	
    '''
    MP-DASH function to enable/disable cellular sub-flow -- assumes as input:
     - timenow: Time when the packet is received
     - packet_size: Size of the packet received in bytes
     - r_wifi: wifi-throughput obtained from holt-winter estimator
     - lte_throughput: historical lte_throughput measured when cellular-subflow is off during this chunk download
     - lte_off: time when lte was turned off during this chunk download.
    This function return 0 to disable the cellular path and 1 to enable the cellular path
    '''

    def on_packet_received(self, time_now, packet_size, r_wifi, lte_throughput, lte_off):
	print "on_packet_received " + str(self) + " " + str(packet_size) + " " + str(self.sent_bytes) + " r_wifi: " + repr(r_wifi)
        n = packet_size
        # At every call of the on-packet received function -- pretend that a MSS is received.
        if n > self.chunk_size - self.sent_bytes:
            n = self.chunk_size - self.sent_bytes

        # Update the total amount of bytes sent
        self.sent_bytes += n

        # Get time that elapses between HTTP Get and HTTP Response
        time_spent = time_now - self.start_time

        # Get Current Buffer Level

        # start a connection to the server
        #ws = create_connection("ws://localhost:9001")

        # If amount of remaining bytes is 0 -- last packet for this chunk
        if (self.chunk_size - self.sent_bytes <= 0):
            # Only send historical lte-throughput if cellular-subflow was de-activate during this chunk download
            if lte_off > 0:
                #ws = create_connection("ws://localhost:9001")
                # Send lte-info to the javascript -- lte_throughput and time lte is off (comma separated).
                self.ws.send("lte_response:" + str(lte_throughput) + "," + str(lte_off))
	    #self.ws.close()

        # Disable MP-Dash if in critical condition
        if (self.buffer_level - time_spent) < self.omega:
            return 1
	
	remaining_bytes = self.chunk_size - self.sent_bytes
	if remaining_bytes <= 0:
	    remaining_bytes = 1500
	    print "OVERHEAD!!!!!!!!!!!! " + str(self)

	print "remaining_bytes: " + repr(remaining_bytes) +  " r_wifi: " + repr(r_wifi) + " deadline: "+str(self.D) + " formula: " + repr(self.alfa * self.D - time_spent)
        if ((self.alfa * self.D - time_spent) * r_wifi) > remaining_bytes:
            # if is_cell_on:
            return 0  # Disable the cellular path

        if ((self.alfa * self.D - time_spent) * r_wifi) <= remaining_bytes:
            # if not is_cell_on:
            return 1  # Enable the cellular path
