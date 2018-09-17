import argparse
import os
import matplotlib.pyplot as plt
import numpy as np
import shlex
import subprocess
import csv
import pandas as pd
import operator
import hw_predictor as hw

class FeaturesDict:
  def __init__(self):
    self.features = {
    'timestamp': [],
    'time_offset': [],
    'src_ip':[],
    'dst_ip': [],
    'src_port': [],
    'dst_port': [],
    'dsn': [],
    'sub_seq': [],
    'win': [],
    'sub_ack': [],
    'total_bytes': [],
    'interface':[],
    'is_out_of_order':[],
    'is_retransmitted':[],
    'is_lost':[],
    'is_handover':[],
    'bssid':[],
    'l2_connect_timestamp':[],
    'l2_disconnect_timestamp':[],
    'l2_connect_offset':[],
    'l2_disconnect_offset':[],
    # 'l3_connection':[],
    # 'l3_disconnect':[]
    }

def get_handover_packets(experiment, server_ip, src_port, client_side_df):
    plt.figure(figsize=(20, 10))
    packet_traces = parse_pcap(experiment,'server', server_ip, '', src_port)

    #Turn dictionary into a dataframe
    df = pd.DataFrame.from_dict(packet_traces)
    #Drop rows with -1 as dsn  d
    df = df[df.dsn != -1]
    #Filter packets with timestamp earlier than experiment timestamp
    df = df[(df['timestamp'] >= float(experiment['timestamp']))]
    #Filter on down-stream packets
    df = df[(df['src_ip'] == server_ip)]

    #Get all unique destination IP
    dest_list = df['dst_ip'].unique()

    #Get list of dsn sent on each ip
    dsn_list = []
    for ip in dest_list:
        dsn_list.append(df[df['dst_ip'] == ip]['dsn'])

    #Get intersection in dsn across lists
    result = set(dsn_list[0]).intersection(*dsn_list)

    #Plot server-side dsn with hand-over packets
    l2_connect = client_side_df.l2_connect_offset.dropna().unique()
    l2_disconnect = client_side_df.l2_disconnect_offset.dropna().unique()
    for x in range(0, len(l2_connect)):
        start = l2_connect[x]
        end = l2_disconnect[x]
        filtered_df = df[(df['time_offset'] >= float(start)) & (df['time_offset'] <= float(end))]

        for ip in dest_list:
            x_normal = []
            y_normal = []
            x_handover = []
            y_handover = []
            offset =  np.array(filtered_df[filtered_df['dst_ip'] == ip]['time_offset'])
            dsn_set = np.array(filtered_df[filtered_df['dst_ip'] == ip]['dsn'])
            for i in range(0, len(dsn_set)):
                if dsn_set[i] in result:
                    x_handover.append(offset[i])
                    y_handover.append(dsn_set[i])
                else:
                    x_normal.append(offset[i])
                    y_normal.append(dsn_set[i])

            plt.scatter(x_normal,y_normal, s = 10, label = ip)
            plt.scatter(x_handover, y_handover, s=10, label=ip+"_handoff", marker = "*")

        #plot server-side dsn
        ax = plt.gca()
        plt.ticklabel_format(useOffset=False)
        handles, labels = ax.get_legend_handles_labels()
        plt.ylabel("Sequence Number")
        plt.xlabel("Time Offset")
        hl = sorted(zip(handles, labels), key=operator.itemgetter(1))
        handles2, labels2 = zip(*hl)
        ax.legend(handles2, labels2)


        plt.title("Server-side DSN over time_["+str(start)+":"+str(end)+"]_"+experiment['timestamp'])
        plt.savefig(experiment['dir']+"/plots/"+"server_side_dsn_over_time_["+str(start)+":"+str(end)+"]_"+experiment['timestamp']+".png", dpi=400,
                    bbox_inches='tight')
        plt.clf()


#This function returns lost, retransmitted, and out-of-order packets
def get_misc_packets(experiment, interface, src_ip, dst_ip, src_port):

    if (experiment[interface+'_txt'] == None):
        tcpdump_out = open(experiment['dir']+interface+"_"+experiment['timestamp']+".txt", "wb")

        # Call tcpdump to convert pcap to .txt file
        args = shlex.split("tcpdump -tt -n -r " + experiment['dir']+experiment[interface+"_pcap"])

        # Save in .txt file
        subprocess.call(args, stdout=tcpdump_out)
        experiment[interface+'_txt'] = interface+"_"+experiment['timestamp']+".txt"



#This function parses the pcap traces to get packet timeline, dsn, subseq, total-bytes
def parse_pcap(experiment, interface, server_ip, device_ip, server_port):

    # tmstp = experiment['timestamp']
    # If pcap -> convert to .txt
    if (experiment[interface+'_txt'] == None):
        tcpdump_out = open(experiment['dir']+interface+"_"+experiment['timestamp']+".txt", "wb")

        # Call tcpdump to convert pcap to .txt file
        args = shlex.split("tcpdump -tt -n -r " + experiment['dir']+experiment[interface+"_pcap"])

        # Save in .txt file
        subprocess.call(args, stdout=tcpdump_out)
        experiment[interface+'_txt'] = interface+"_"+experiment['timestamp']+".txt"

    packet_traces = {'timestamp': [],
                     'time_offset': [],
                     'src_ip':[],
                     'dst_ip': [],
                     'src_port': [],
                     'dst_port': [],
                     'dsn': [],
                     'sub_seq': [],
                     'win': [],
                     'sub_ack': [],
                     'total_bytes': [],
                     'mptcp_len': [],
                     'interface':[]}
    # Open the tcpdump file
    with open(experiment['dir']+experiment[interface+"_txt"], 'r') as dump_file:
        # read as CSV file delimited by space
        reader = csv.reader(dump_file, delimiter=' ')
        for row in reader:
            try:
                # Check if row corresponds to a packet (upstream/downstream)
                if len(row) > 0 and 'length' in row and 'IP' in row:
                    if 'UDP' in row:
                        continue

                    # Get packet timestamp
                    timestamp = float(row[0])

                    # Get the index of the length value
                    length_idx = row.index('length') + 1
                    length = 0
                    if ':' in row[length_idx] or '+' in row[length_idx]:
                        length = int(row[length_idx][:-1])
                    else:
                        length = int(row[length_idx])

                    #Get sequence number
                    seq_idx = -1
                    if 'seq' in row:
                        seq_idx = row.index('seq') + 1
                    subseq = -1
                    sub_seq_end = -1
                    if seq_idx != -1:
                        if ':' not in row[seq_idx]:
                            subseq = int(row[seq_idx][:-1])
                        else:
                            subseq = int(row[seq_idx].split(':')[0])
                            seq_end = int(row[seq_idx].split(':')[1][:-1])

                    #Get ack number
                    ack_idx = -1
                    ack     = -1
                    if 'ack' in row:
                        ack_idx = row.index('ack') + 1
                        ack = int(row[ack_idx][:-1])

                    #Get window size
                    win_idx = -1
                    win     = -1
                    if 'win' in row:
                        win_idx = row.index('win') + 1
                        win = int(row[win_idx][:-1])

                    #Get Data Sequence Number
                    dss_idx = -1
                    dss_seq = -1
                    mptcp_len = -1

                    if 'subseq' in row:
                        dss_idx = row.index('subseq') - 1
                        dss_seq = int(row[dss_idx])
                        mptcp_len = int(row[dss_idx+4])

                    # Get source IP
                    source_ip_tup = row[2]

                    # Get destination IP
                    dest_ip_tup = row[4][:-1]

                    # downstream packets
                    if server_ip in source_ip_tup or server_ip in dest_ip_tup:
                        # get destination port number
                        tup = dest_ip_tup.split('.')
                        if len(tup) < 5:
                            continue
                        extracted_dst_port = tup[4]
                        extracted_dst_ip = '.'.join(tup[:-1])

                        # get source port number
                        tup = source_ip_tup.split('.')
                        if len(tup) < 5:
                            continue
                        extracted_src_port = tup[4]
                        extracted_src_ip = '.'.join(tup[:-1])

                        # Check if port corresponds to current app
                        if (server_port == extracted_src_port) or server_port == extracted_dst_port:
                            packet_traces['timestamp'].append(float(timestamp))
                            packet_traces['time_offset'].append(float(timestamp) - float(experiment['timestamp']))
                            packet_traces['src_ip'].append(extracted_src_ip)
                            packet_traces['dst_ip'].append(extracted_dst_ip)
                            packet_traces['src_port'].append(extracted_src_port)
                            packet_traces['dst_port'].append(extracted_dst_port)
                            packet_traces['dsn'].append(dss_seq)
                            packet_traces['sub_seq'].append(subseq)
                            packet_traces['win'].append(win)
                            packet_traces['sub_ack'].append(ack)
                            packet_traces['total_bytes'].append(length)
                            packet_traces['mptcp_len'].append(mptcp_len)
                            packet_traces['interface'].append(interface)

                    else:
                        continue
            except Exception as e:
                print e.message

    return packet_traces

#This function parses the wpa-supplication to get l2-connection and l2-disconnection
def parse_wpa_supplicant(file):
    bssid_list = {}
    index = 0
    flag_start_connection = 0
    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            # if line.find("nl80211: Set supplicant port authorized for") != -1:
            if line.find("CTRL-EVENT-CONNECTED") != -1:
                flag_start_connection = 1
                timestamp = (line.split(" ")[0]).replace(":","")
                # bssid = line.split(" ")[7].replace("\n","")
                bssid = line.split(" ")[6].replace("\n", "")
                bssid_list[index] = {'bssid': bssid, 'start': timestamp, 'end': -1, 'duration': -1}
                # index += 1
            if line.find("CTRL-EVENT-DISCONNECTED") != -1:
                if flag_start_connection == 1:
                    timestamp = (line.split(" ")[0]).replace(":", "")
                    bssid = (line.split(" ")[3]).split("=")[1]
                    if(bssid_list[index]['bssid'].strip() == bssid.strip()):
                        bssid_list[index]['end'] = timestamp
                        bssid_list[index]['duration'] = float(bssid_list[index]['end']) - float(bssid_list[index]['start'])
                        flag_start_connection = 0
                        index +=1

    return bssid_list

#This function processes a single experiment and generates a pickle file
def process_experiment(experiment, wifi_client_ip, lte_client_ip, server_ip, client_port_number, server_port_number):
    ft = FeaturesDict()
    #Parse Wifi Pcap
    print "Parse Wifi Pcap..."
    wifi_packets = parse_pcap(experiment, 'wifi', server_ip, wifi_client_ip, server_port_number)
    #Append to features dictionary
    ft.features['timestamp'].extend(wifi_packets['timestamp'])
    ft.features['time_offset'].extend(wifi_packets['time_offset'])
    ft.features['src_ip'].extend(wifi_packets['src_ip'])
    ft.features['dst_ip'].extend(wifi_packets['dst_ip'])
    ft.features['src_port'].extend(wifi_packets['src_port'])
    ft.features['dst_port'].extend(wifi_packets['dst_port'])
    ft.features['dsn'].extend(wifi_packets['dsn'])
    ft.features['sub_seq'].extend(wifi_packets['sub_seq'])
    ft.features['win'].extend(wifi_packets['win'])
    ft.features['sub_ack'].extend(wifi_packets['sub_ack'])
    ft.features['total_bytes'].extend(wifi_packets['total_bytes'])
    ft.features['interface'].extend(wifi_packets['interface'])
    print "Done parsing Wifi Pcap"

    #Parse LTE Pcap
    print "Parse LTE Pcap..."
    lte_packets = parse_pcap(experiment, 'lte', server_ip, lte_client_ip, server_port_number)
    #Append to features dictionary
    ft.features['timestamp'].extend(lte_packets['timestamp'])
    ft.features['time_offset'].extend(lte_packets['time_offset'])
    ft.features['src_ip'].extend(lte_packets['src_ip'])
    ft.features['dst_ip'].extend(lte_packets['dst_ip'])
    ft.features['src_port'].extend(lte_packets['src_port'])
    ft.features['dst_port'].extend(lte_packets['dst_port'])
    ft.features['dsn'].extend(lte_packets['dsn'])
    ft.features['sub_seq'].extend(lte_packets['sub_seq'])
    ft.features['win'].extend(lte_packets['win'])
    ft.features['sub_ack'].extend(lte_packets['sub_ack'])
    ft.features['total_bytes'].extend(lte_packets['total_bytes'])
    ft.features['interface'].extend(lte_packets['interface'])
    print "Done parsing LTE Pcap"

    #Append empty arrays -- to allow merge
    empty_array = [None] * len(ft.features['timestamp'])
    false_array = [False] * len(ft.features['timestamp'])
    ft.features['bssid'].extend(empty_array)
    ft.features['l2_connect_timestamp'].extend(empty_array)
    ft.features['l2_disconnect_timestamp'].extend(empty_array)
    ft.features['l2_connect_offset'].extend(empty_array)
    ft.features['l2_disconnect_offset'].extend(empty_array)
    ft.features['is_out_of_order'].extend(false_array)
    ft.features['is_retransmitted'].extend(false_array)
    ft.features['is_lost'].extend(false_array)
    ft.features['is_handover'].extend(false_array)

    #Convert features to dataframe
    print "Merge into data frame..."
    df = pd.DataFrame(data=ft.features)

    #sort dataframe by timestamp
    print "Sort data frame..."
    df = df.sort_values('timestamp')

    #parse wpa-supplicant log to get set of all APs
    print "Parse wpa-supplicant log..."
    ap_list = parse_wpa_supplicant(experiment['dir']+experiment['wpa_supplicant'])

    #Associate AP to packet-traces
    print "Label dataframe with AP bssid..."
    for i in ap_list:
        start_time = float(ap_list[i]['start'])
        end_time = float(ap_list[i]['end'])

        # For each row in df with packet-timeline >= start-time and <= end-time and interface = wifi, set bssid to ap
        df.loc[(df['timestamp'] >= start_time)&(df['timestamp'] <= end_time)&(df['interface'] == 'wifi'), 'bssid'] = ap_list[i]['bssid']
        df.loc[(df['timestamp'] >= start_time) & (df['timestamp'] <= end_time) & (df['interface'] == 'wifi'), 'l2_connect_timestamp'] = start_time
        df.loc[(df['timestamp'] >= start_time) & (df['timestamp'] <= end_time) & (df['interface'] == 'wifi'), 'l2_connect_offset'] = start_time - float(experiment['timestamp'])
        df.loc[(df['timestamp'] >= start_time) & (df['timestamp'] <= end_time) & (df['interface'] == 'wifi'), 'l2_disconnect_timestamp'] = end_time
        df.loc[(df['timestamp'] >= start_time) & (df['timestamp'] <= end_time) & (df['interface'] == 'wifi'), 'l2_disconnect_offset'] = end_time - float(experiment['timestamp'])

    # Save dataframe to pickles    print "Save dataframe to pkl file"
    df.to_pickle(experiment['dir']+"processed_experiment_"+experiment['timestamp']+".pkl")

    print "Done processing experiment!"

#This function plots sequence number overtime
def plot_feature_overtime(df, feature, start, end, server_ip, server_port, direction, path, timestamp):

    plt.figure(figsize=(20, 10))

    bssid_list = df.bssid.dropna().unique()

    #filter df per specified duration
    filtered_df = df[(df['time_offset'] >= float(start)) & (df['time_offset'] <= float(end))]

    if direction == 'upstream':
        filtered_df = filtered_df[(df['dst_ip'] == server_ip) & (filtered_df['dst_port'] == server_port)]
    else:
        filtered_df = filtered_df[(filtered_df['src_ip'] == server_ip) & (filtered_df['src_port'] == server_port)]
        # filter rows with -1 as dsn
        filtered_df = filtered_df[filtered_df.dsn != -1]

    for ap in bssid_list:
        x_array = filtered_df[filtered_df['bssid'] == ap]['time_offset']
        y_array = filtered_df[filtered_df['bssid'] == ap][feature]

        # p = plt.plot(x_array,y_array, label = ap, linewidth=2.0)
        if len(x_array) > 0:
            plt.scatter(np.asarray(x_array), np.asarray(y_array), label=ap, s=10, marker="^")

    # Plot l2 connection time
    l2_connect = filtered_df.l2_connect_offset.dropna().unique()
    for xc in l2_connect:
        plt.axvline(x=xc, linestyle=":")

    # Plot l2 disconnection time
    l2_disconnect = filtered_df.l2_disconnect_offset.dropna().unique()
    for xc in l2_disconnect:
        plt.axvline(x=xc, linestyle="-")

    # Plot lte dsn
    lte_timeline = filtered_df[filtered_df['interface'] == 'lte']['time_offset']
    lte_dsn = filtered_df[filtered_df['interface'] == 'lte'][feature]
    plt.scatter(lte_timeline, lte_dsn, label='lte', s=10, marker='+')

    ax = plt.gca()
    plt.ticklabel_format(useOffset=False)

    handles, labels = ax.get_legend_handles_labels()
    plt.ylabel(feature)
    plt.xlabel("Time Offset")
    hl = sorted(zip(handles, labels), key=operator.itemgetter(1))
    handles2, labels2 = zip(*hl)
    ax.legend(handles2, labels2)

    plt.title(feature+" over time_"+timestamp)
    plt.savefig(path+feature+"_over_time_["+str(start)+":"+str(end) + "]_"+timestamp+".png", dpi=400, bbox_inches='tight')
    plt.clf()


def plot_interarrival_time_cdf(df, server_ip, server_port, path, timestamp):
    plt.figure(figsize=(20, 10))

    inter_arrival_time = []
    #filter on downstream packets
    filtered_df = df[(df['src_ip'] == server_ip) & (df['src_port'] == server_port)]
    # filter rows with -1 as dsn
    filtered_df = filtered_df[filtered_df.dsn != -1]

    timestamps = np.array(filtered_df['timestamp'])
    for i in range(1, len(timestamps)):
        #Get inter-arrival time in milliseconds
        inter_arrival_time.append((float(timestamps[i]) - float(timestamps[i-1]))*1000)

    #plot cdf of inter-arrival time
    data_set = sorted(set(inter_arrival_time))
    yvals = np.arange(len(data_set))/float(len(data_set) - 1)
    plt.plot(data_set, yvals, linestyle='-', marker="*", color='r',label='inter-arrival time')
    plt.xlabel("msec")
    plt.legend()
    plt.title("Packets Inter-arrival Time_"+timestamp)
    plt.savefig(path+"packets_iat_"+timestamp+".png", dpi=400,bbox_inches='tight')
    plt.clf()


#This function calls multiple plot functions
def plot_experiment(df, start, end, server_ip, server_port, path, timestamp):

    plot_feature_overtime(df,'dsn', 0, df['time_offset'][len(df['time_offset']) -1], server_ip, server_port, 'downstream', path, timestamp)

    plot_feature_overtime(df,'win', 0, df['time_offset'][len(df['time_offset']) - 1], server_ip, server_port, 'upstream', path, timestamp)

    #plot per-ap dsn
    l2_connect = df.l2_connect_offset.dropna().unique()
    l2_disconnect = df.l2_disconnect_offset.dropna().unique()
    for x in range(0, len(l2_connect)):
        plot_feature_overtime(df,'dsn', l2_connect[x], l2_disconnect[x], server_ip, server_port, 'downstream', path, timestamp)
        plot_feature_overtime(df,'win', l2_connect[x], l2_disconnect[x], server_ip, server_port, 'upstream', path, timestamp)

    #plot inter-arrival time between packets
    plot_interarrival_time_cdf(df, server_ip, server_port, path, timestamp)

def process_experiments(folder, wifi_client_ip, lte_client_ip, server_ip, client_port_number, server_port_number):
    print "Process Experiments in director ",folder
    #List all experiments under directory
    dirs = os.listdir(folder)

    # Create an array of experiments
    experiments = {}

    # Loop through experiments
    for dir in dirs:
        print "Experiment ", dir
        # try:
        currentDir = folder+dir+"/"
        if os.path.isdir(currentDir):
            # print 'Processing directory', currentDir
            experiments[dir] = {'dir': currentDir,
                                'timestamp': dir,
                                'ip_monitor': None,
                                'roamingd': None,
                                'wifi_pcap': None,
                                'wifi_txt': None,
                                'lte_pcap': None,
                                'lte_txt': None,
                                'server_pcap': None,
                                'server_txt': None,
                                'wpa_supplicant': None,
                                'video_metrics': None,
                                'ping_log': None,
                                'processed_experiment':None,
                                'ap_connection':None}

            #Populate experiment
            fs = os.listdir(currentDir)
            print "Populate list of files in experiment ",dir
            for f in fs:
                # print "Parsing file ", f
                if f.startswith("ip_monitor"):
                    experiments[dir]['ip_monitor'] = f
                elif f.startswith('roamingd'):
                    experiments[dir]['roamingd'] = f
                elif f.startswith('wifi') & f.endswith('.pcap'):
                    experiments[dir]['wifi_pcap'] = f
                elif f.startswith('wifi') & f.endswith('.txt'):
                    experiments[dir]['wifi_txt'] = f
                elif f.startswith('lte') & f.endswith('.pcap'):
                    experiments[dir]['lte_pcap'] = f
                elif f.startswith('lte') & f.endswith('.txt'):
                    experiments[dir]['lte_txt'] = f
                elif f.startswith('wpa_supplicant'):
                    experiments[dir]['wpa_supplicant'] = f
                elif f.startswith("video"):
                    experiments[dir]['video_metrics'] = f
                elif f.startswith("ping"):
                    experiments[dir]['ping_log'] = f
                elif f.startswith('server') & f.endswith('.pcap'):
                    experiments[dir]['server_pcap'] = f
                elif f.startswith('server') & f.endswith('.txt'):
                    experiments[dir]['server_txt'] = f
                # elif f.startswith("ap") & f.endswith(".csv"):
                #     experiments[dir]['ap_connection'] = f
                elif f.startswith("processed") & f.endswith(".pkl"):
                    experiments[dir]['processed_experiment'] = f

            # Find if experiment is already processed
            if(experiments[dir]['processed_experiment'] == None):
                print "No pickles found, process experiment"
                #Process Experiment
                process_experiment(experiments[dir], wifi_client_ip, lte_client_ip, server_ip, client_port_number, server_port_number)
                experiments[dir]['processed_experiment'] = "processed_experiment_"+experiments[dir]['timestamp']+".pkl"

            #load pickle
            print "Plotting..."
            df = pd.read_pickle(currentDir+experiments[dir]['processed_experiment'])
            filtered_df = df[(df['src_ip'] == server_ip) & (df['src_port'] == server_port_number)]
            print "Total Bytes downloaded over LTE",np.sum(filtered_df[filtered_df['interface'] == 'lte']['total_bytes'])
            print "Total Bytes downloaded over Wifi",np.sum(filtered_df[filtered_df['interface'] == 'wifi']['total_bytes'])

            #Filter on downstream packets
            filtered_df = df[(df['src_ip'] == server_ip) & (df['src_port'] == server_port_number)]
            hw.get_throughput_prediction(filtered_df, currentDir+"plots/")

            # get handover packets + plot server-side pcap
            # get_handover_packets(experiments[dir], '172.31.46.30', server_port_number, df)

            #Plot Experiment
            plot_experiment(df, -1, -1, server_ip, server_port_number ,currentDir+"plots/", dir)

    print "Done processing experiments"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-F', '--directory', type=str, required=True, help="directory with experiments")
    parser.add_argument('-WCI', '--wifi_client_ip', type=str, required=False, help="wifi client ip")
    parser.add_argument('-LCI', '--lte_client_ip', type=str, required=False, help="lte client ip")
    parser.add_argument('-SI', '--server_ip', type=str, required=False, help="server ip")
    parser.add_argument('-CP', '--client_port_number', type=str, required=False, help="client port number")
    parser.add_argument('-SP', '--server_port_number', type=str, required=False, help="server port number")
    args = vars(parser.parse_args())
    process_experiments(args['directory'], args['wifi_client_ip'], args['lte_client_ip'],  args['server_ip'], args['client_port_number'], args['server_port_number'])


if __name__ == '__main__':
    main()
