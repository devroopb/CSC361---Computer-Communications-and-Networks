# CSC361 - Assignment 3
# Devroop Banerjee
# V00837868

import dpkt
import socket
import datetime
import argparse
import statistics

# Return true if data is an instance of UDP or ICMP
def validity(data):
    if isinstance(data, dpkt.udp.UDP) or (isinstance(data, dpkt.icmp.ICMP) and (data.type == 8)): return True
    return False

def analyse(filename):
    file = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(file)

    # Highest TTL in packet right now
    TTLcount = 0
    TTL_C = [0] * 100
    # Probes per TTL
    TTLprobes = 0
    packetsOut = {}
    
    srcNode = ""
    ultimateNode = ""
    intermediateIP = []
    intermediateIP_S = set()

    datagrams = {}
    fragmentationID = {}
    # List of protocols
    protocols = set()
    baseTS = 0

    count = 0
    for ts, buf in pcap:
        if count == 0: baseTS = ts

        ethernetOBJ = dpkt.ethernet.Ethernet(buf)
        IP_OBJ = ethernetOBJ.data
        count += 1

        if not isinstance(ethernetOBJ.data, dpkt.ip.IP): continue
        protocols.add(IP_OBJ.p)

        srcIP = socket.inet_ntoa(IP_OBJ.src)
        dstIP = socket.inet_ntoa(IP_OBJ.dst)

        currentTTL = IP_OBJ.ttl
        if currentTTL < TTLcount:
            print("Packet out of order", count)
            continue
        
        if (currentTTL == TTLcount + 1) and validity(IP_OBJ.data):
            TTLcount = currentTTL
            if TTLcount == 1:
                srcNode = srcIP
                ultimateNode = dstIP

        if (currentTTL == TTLcount) and (validity(IP_OBJ.data)) and (TTLcount == 1): TTLprobes += 1

        # From source node
        if (currentTTL <= TTLcount + 1) and (srcIP == srcNode) and (dstIP == ultimateNode):
            fragID = IP_OBJ.id
            additionalFrags = bool(IP_OBJ.off & dpkt.ip.IP_MF)
            fragOffset = (IP_OBJ.off & dpkt.ip.IP_OFFMASK) * 8
            
            if fragID not in datagrams: datagrams[fragID] = {'count':0, 'offset':0, 'send_times':[]}
            
            if additionalFrags or fragOffset > 0:
                datagrams[fragID]['count'] += 1
                datagrams[fragID]['offset'] = fragOffset
            
            datagrams[fragID]['send_times'].append(ts)
            # Placeholders which are to be removed later
            for i in range(5): intermediateIP.append("")

            if isinstance(IP_OBJ.data, dpkt.icmp.ICMP) and (IP_OBJ.data.type == 8):
                ICMP_OBJ = IP_OBJ.data
                fragmentationID[ICMP_OBJ['echo'].seq] = fragID
                packetsOut[ICMP_OBJ['echo'].seq] = {'ttl':IP_OBJ.ttl, 'ttl_adj':TTL_C[IP_OBJ.ttl]}
                TTL_C[IP_OBJ.ttl] += 1

            if isinstance(IP_OBJ.data, dpkt.udp.UDP):
                UDP_OBJ = IP_OBJ.data
                fragmentationID[UDP_OBJ.dport] = fragID
                packetsOut[UDP_OBJ.dport] = {'ttl':IP_OBJ.ttl, 'ttl_adj':TTL_C[IP_OBJ.ttl]}
                TTL_C[IP_OBJ.ttl] += 1

        # Back to source
        elif dstIP == srcNode:
            if isinstance(IP_OBJ.data, dpkt.udp.UDP): UDP_OBJ = IP_OBJ.data
            
            if isinstance(IP_OBJ.data, dpkt.icmp.ICMP):
                ICMP_OBJ = IP_OBJ.data
                ICMPtype = ICMP_OBJ.type
                dataPkt = ICMP_OBJ.data
                
                if ICMPtype == 0 or ICMPtype == 8:
                    # Ping Reply
                    seq = dataPkt.seq
                    packetsOut[seq]['ip'] = srcIP
                    packetsOut[seq]['fragID'] = fragmentationID[seq]
                    packetsOut[seq]['reply_time'] = ts
                    continue
                
                dataPkt = ICMP_OBJ.data.data.data
                
                if isinstance(dataPkt, dpkt.icmp.ICMP) and (dataPkt['echo'].seq in packetsOut):
                    seq = dataPkt['echo'].seq
                    packetsOut[seq]['ip'] = srcIP
                    packetsOut[seq]['fragID'] = fragmentationID[seq]
                    packetsOut[seq]['reply_time'] = ts
                    
                    if ICMPtype == 11 and (srcIP not in intermediateIP_S):
                        ttl = packetsOut[seq]['ttl']
                        ttl_adj = packetsOut[seq]['ttl_adj']
                        intermediateIP[(ttl * 5) - 1 + ttl_adj] = srcIP
                        intermediateIP_S.add(srcIP)

                if isinstance(dataPkt, dpkt.udp.UDP) and (dataPkt.dport in packetsOut):
                    packetsOut[dataPkt.dport]['ip'] = srcIP
                    packetsOut[dataPkt.dport]['fragID'] = fragmentationID[dataPkt.dport]
                    packetsOut[dataPkt.dport]['reply_time'] = ts
                    
                    if ICMPtype == 11 and (srcIP not in intermediateIP_S):
                        ttl = packetsOut[dataPkt.dport]['ttl']
                        ttl_adj = packetsOut[dataPkt.dport]['ttl_adj']
                        intermediateIP[(ttl * 5) - 1 + ttl_adj] = srcIP
                        intermediateIP_S.add(srcIP)
        else: continue

    while "" in intermediateIP: intermediateIP.remove("")

    rdata = {}
    rdata['TTLprobes'] = TTLprobes
    rdata['intermediateIP'] = intermediateIP_S


    print("The IP address of the source node: ", srcNode)
    print("The IP address of ultimate destination node: ", ultimateNode)
    print("The IP addresses of the intermediate destination nodes:")

    x = 1
    for ip in intermediateIP:
        print("     router ", x, ": ", ip)
        x += 1

    print("The values in the protocol field of IP headers: ")
    protocol_table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
    for protocol in protocols: print("     ", protocol_table[protocol])

    print("Datagrams:")
    for id, datagram in datagrams.items(): print("     #" + str(id) + ":   " + "Fragments: " + str(datagram["count"]) + "   Final offset: " + str(datagram["offset"]))

    IP_RTTS = {}
    for port, packet in packetsOut.items():
        if 'fragID' not in packet: continue
        fragID = packet['fragID']
        send_times = datagrams[fragID]['send_times']
        if 'reply_time' not in packet: continue
        reply_time = packet['reply_time']
        ip = packet['ip']
        if ip not in IP_RTTS: IP_RTTS[ip] = []
        for send_time in send_times: IP_RTTS[ip].append(reply_time - send_time)
    rdata['rtt_means'] = []

    for ip, rtts in IP_RTTS.items():
        print("The avg RTT between ", srcNode, " and ", ip, " is: ", statistics.mean(rtts), "s, the s.d. is: ", statistics.pstdev(rtts), "s")
        rdata['rtt_means'].append(statistics.mean(rtts))

    return rdata

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read and report data on intermediate hosts and fragmentation')
    parser.add_argument('filename')
    args = parser.parse_args()
    filename = args.filename

    analyse(filename)