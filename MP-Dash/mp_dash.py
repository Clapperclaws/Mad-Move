from websocket import create_connection

class mp_dash:
    ''' MP-DASH is initialize with:
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
        self.packet_size = 1500

        #set the deadline
        if(is_rate_based):
            self.deadline_window = float(chunk_size * 8)/float(bit_rate)
        else:
            self.deadline_window = chunk_duration

        #set Omega & Phi based on ABR algorithm type
        if(is_buffer_based):
            self.phi = 76 #Total buffer capacity (80) - segment-size (4)
            self.omega = 9 #Buffer-length that maps to the lowest bitrate (reservoir = 5 sec) + segment-size
        else:
            self.phi = 64 #80% of total buffer-capacity
            self.omega = 32 # Minimum set to be 40% of buffer-capacity


    #MP-DASH function to enable/disable cellular sub-flow -- assumes as input, timenow, wifi-throughput,
    # amount of sent-bytes, boolean if Cellular subflow is enabled/disabled
    # This function return 0 to disable the cellular path and 1 to enable the cellular path
    def on_packet_received(self, time_now, is_cell_on, r_wifi, lte_throughput, lte_off):
        n = 0
        #At every call of the on-packet received function -- pretend that a MSS is received.
        if self.chunk_size - self.sent_bytes > self.packet_size:
            n = self.packet_size
        else:
            n = self.chunk_size - self.sent_bytes

        # Update the total amount of bytes sent
        self.sent_bytes += n

        # Get time that elapses between HTTP Get and HTTP Response
        time_spent = time_now - self.start_time

        #Get Current Buffer Level

        # start a connection to the server
        ws = create_connection("ws://localhost:9001")
        # Request Buffer Level from Javascript
        ws.send("Buffer_Level")
        # Read Reply from Server
        result = ws.recv()
        # This stripping & trimming is to handle the javascript output function -- could be modified
        buffer_level = float(str.strip(result.split(':')[1]))
        ws.close()


        #Adjust the deadline window
        D = self.deadline_window
        if buffer_level > self.phi:
            D = buffer_level + (buffer_level - self.phi)

        #If amount of remaining bytes is 0 -- last packet for this chunk
        if(self.chunk_size - self.sent_bytes <= 0):
            ws = create_connection("ws://localhost:9001")
            #Send lte-info to the javascript -- lte_throughput and time lte is off (comma separated).
            ws.send("lte_response:"+str(lte_throughput)+","+str(lte_off))

        #Disable MP-Dash if in critical condition
        if buffer_level < self.omega:
            return is_cell_on

        if ((self.alfa * D - time_spent) * r_wifi) > (self.chunk_size - self.sent_bytes):
            # if is_cell_on:
                return 0 # Disable the cellular path

        if ((self.alfa * D - time_spent) * r_wifi) <= (self.chunk_size - self.sent_bytes):
            # if not is_cell_on:
                return 1 # Enable the cellular path
