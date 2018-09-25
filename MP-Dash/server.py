from websocket_server import WebsocketServer

clients = {}

def client_left(client, server):
    msg = "Client (%s) left" % client['id']
    print (msg)
    try:
        clients.pop(client['id'])
    except:
        print ("Error in removing client %s" % client['id'])
    for cl in clients.values():
        server.send_message(cl, msg)


def new_client(client, server):
    msg = "New client (%s) connected" % client['id']
    print (msg)
    for cl in clients.values():
        server.send_message(cl, msg)
    clients[client['id']] = client


def msg_received(client, server, msg):
    last_lte_info = "lte_response:0,0"
    msg = "Client (%s) : %s" % (client['id'], msg)
    print (msg)
    if("buffer" in msg):
        clientid = client['id']
        for cl in clients:
            if cl != clientid:
                cl = clients[cl]
                server.send_message(cl, msg)
    if("lte_request" in msg):
        clientid = client['id']
        server.send_message(clients[clientid], last_lte_info)
    if ("lte_response" in msg):
        last_lte_info = msg


server = WebsocketServer(9001)
server.set_fn_client_left(client_left)
server.set_fn_new_client(new_client)
server.set_fn_message_received(msg_received)
server.run_forever()



