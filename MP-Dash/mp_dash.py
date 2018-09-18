from websocket import create_connection

class mp_dash:

    def __init__(self, start_time, chunk_size, alfa):

        self.chunk_size = chunk_size
        self.star_time = start_time
        self.remaining_bytes = chunk_size
        self.alfa = alfa

        # Get Buffer Level from JS
        #start a connection to the server
        ws = create_connection("ws://localhost:9001")
        #Request Buffer Level from Javascript
        ws.send("Buffer_Level")
        #Read Reply from Server
        result = ws.recv()
        #This stripping & trimming is to handle the javascript output function -- could be modified
        self.buffer_level = float(str.strip(result.split(':')[1]))
        print self.buffer_level
        ws.close()

    #MP-DASH function to enable/disable cellular sub-flow -- assumes as input, timenow, wifi-throughput,
    # amount of sent-bytes, boolean if Cellular subflow is enabled/disabled
    def on_packet_received(self, time_now, r_wifi, sent_bytes, is_cell_on):

        time_spent = time_now - self.star_time
        self.remaining_bytes = self.remaining_bytes - sent_bytes

        if ((self.alfa * self.buffer_level - time_spent) * r_wifi) > (self.chunk_size - sent_bytes):
            if is_cell_on:
                return 0

        if ((self.alfa * self.buffer_level - time_spent) * r_wifi) < (self.chunk_size - sent_bytes):
            if not is_cell_on:
                return 1
