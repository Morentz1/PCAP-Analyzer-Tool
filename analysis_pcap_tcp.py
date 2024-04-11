import dpkt
import sys
from socket import inet_ntoa

SENDER = "130.245.145.12"
RECEIVER = "128.208.2.198"
TCP_FLOWS = {} # flow -> packet

def analyze_pcap(pcap_file):

    # open file to read the bytes
    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            # get packet
            packet = dpkt.ethernet.Ethernet(buf).data
            # allow only TCP packets
            if isinstance(packet.data, dpkt.tcp.TCP):
                sport = packet.data.sport
                src = inet_ntoa(packet.src)
                dport = packet.data.dport
                dst = inet_ntoa(packet.dst)
                # make flow tuple
                flow = (sport, src, dport, dst)
                # if SYn packet
                if packet.data.flags == 2:
                    if flow not in TCP_FLOWS:
                        TCP_FLOWS[flow] = []
                    # add ts, packet tuple to the flow_key
                    TCP_FLOWS[flow].append((timestamp, packet))
                else:
                    rev_flow = (dport, dst, sport, src)
                    for flow_key in TCP_FLOWS.keys():
                        if flow == flow_key or rev_flow == flow_key:
                            TCP_FLOWS[flow_key].append((timestamp, packet))          

if __name__ == "__main__":
    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)
    
    print("Number of TCP Flows:", str(len(TCP_FLOWS)))
    count = 1
    for flow in TCP_FLOWS:
        print("-" * 40)
        print("TCP Flow ", count)
        print()
        print("Source IP:", flow[1])
        print("Source Port:", flow[0])
        print("Destination IP:", flow[3])
        print("Destination Port:", flow[2])
        print()
        transaction1 = TCP_FLOWS[flow][3][1]
        transaction2 = TCP_FLOWS[flow][4][1]
        print("Transaction 1:")
        print("Sequence Num:", str(transaction1.data.seq), )
        print("Acknowledgement Num:", str(transaction1.data.ack))
        print("Receive Window Size:",str(transaction1.data.win))
        print()
        print("Transaction 2:")
        print("Sequence Num:", str(transaction2.data.seq))
        print("Acknowledgement Num:", str(transaction2.data.ack))
        print("Receive Window Size:", str(transaction2.data.win))
        print()
        throughput = 0 # throughput
        congestion_windows = [] # keep track of congestion window
        transmissions = [] # keep track of transmission
        retransmissions = [] # keep track of retransmission
        packets = TCP_FLOWS[flow][3:len(TCP_FLOWS[flow])] # ignore establish connection packet
        rtt_end_time = packets[0][0] + (TCP_FLOWS[flow][1][0] - TCP_FLOWS[flow][0][0]) # first packet + rtt calculated from establishing connection
        triple_retransmit = 0 # triple ack
        retransmits = 0 # 
        ack = -1 # ack 
        ack_time = 0 # ack timestamp
        rtt_count = 0 # rtt counts
        for packet in packets:
            pkt = packet[1]
            # record strictly from Sender's ip
            if inet_ntoa(pkt.src) == SENDER:
                # retransmission count calculation
                for rt in retransmissions:
                    if pkt.data.seq == rt[1]:
                        triple_retransmit += 1
                        break
                
                # transmission list
                tup = (pkt.data.seq, pkt.data.ack)
                if not tup in transmissions:
                    transmissions.append(tup)
                else:
                    retransmits += 1

                # congestion window calculation
                if len(congestion_windows) < 3:
                    if packet[0] <= rtt_end_time:
                        rtt_count += 1
                    else:
                        congestion_windows.append(rtt_count)
                        rtt_end_time = packet[0] + (TCP_FLOWS[flow][1][0] - TCP_FLOWS[flow][0][0])
                        rtt_count = 0
                
                # throughput calculation
                throughput += len(pkt.data)
                if pkt.data.flags & 1: # FIN
                    throughput /= packet[0] - TCP_FLOWS[next(iter(TCP_FLOWS.keys()))][0][0]
                    break
            else:
                if pkt.data.flags & 0x010: # check if ACK
                    if ack == pkt.data.ack: # check against current ACK
                        tup = (ack_time, ack) 
                        # retransmission list
                        # if ack tup does not exist, add it
                        if tup not in retransmissions:
                            retransmissions.append(tup)
                    else:
                        # uupdate current ack
                        ack = pkt.data.ack
                        ack_time = packet[0]


        print("Throughput:", str(throughput), "bytes/sec")
        print("Congestion Windows:", str(congestion_windows))
        print("Number of Triple Dup ACK:", str(triple_retransmit))
        print("Number of Timeouts:", str(retransmits-triple_retransmit))
        count += 1



