from websocket import create_connection

class mp_dash:

    def __init__(self, start_time, chunk_size, alfa):

        self.chunk_size = chunk_size # Synonymous to S - video chunk size
        self.sent_bytes = 0 # Total amount of bytes sent so far
        self.start_time = start_time # Time when HTTP Get request is sent

        self.alfa = alfa # Alfa is used to compensate the estimation inaccuracy of Wifi Throughput
        self.packet_size = 1500

        # Get Buffer Level from JS
        #start a connection to the server
        ws = create_connection("ws://localhost:9001")
        #Request Buffer Level from Javascript
        ws.send("Buffer_Level")
        #Read Reply from Server
        result = ws.recv()
        #This stripping & trimming is to handle the javascript output function -- could be modified
        self.deadline_window = float(str.strip(result.split(':')[1]))
        ws.close()

    #MP-DASH function to enable/disable cellular sub-flow -- assumes as input, timenow, wifi-throughput,
    # amount of sent-bytes, boolean if Cellular subflow is enabled/disabled
    # This function return 0 to disable the cellular path and 1 to enable the cellular path
    def on_packet_received(self, time_now, r_wifi, lte_throughput, lte_off):
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

        #If amount of remaining bytes is 0 -- last packet for this chunk
        if(self.chunk_size - self.sent_bytes <= 0):
            ws = create_connection("ws://localhost:9001")
            #Send lte-info to the javascript -- lte_throughput and time lte is off (comma separated).
            ws.send("lte_response:"+str(lte_throughput)+","+str(lte_off))

        if ((self.alfa * self.deadline_window - time_spent) * r_wifi) > (self.chunk_size - self.sent_bytes):
            # if is_cell_on:
                return 0 # Disable the cellular path

        if ((self.alfa * self.deadline_window - time_spent) * r_wifi) <= (self.chunk_size - self.sent_bytes):
            # if not is_cell_on:
                return 1 # Enable the cellular path
