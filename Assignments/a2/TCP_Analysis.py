# CSC361 - Assignment 2 - TCP Traffic Analysis
# Devroop Banerjee
# V00837868

# References:
# https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
# https://www.binarytides.com/python-packet-sniffer-code-linux/
# http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html


import socket, argparse, datetime, dpkt

# Makes (srcIP:srcPORT ; dstIP:dstPORT) combinations
def stringify(srcIP, srcPORT, dstIP, dstPORT):
	stringVariable = ""
	if(srcIP < dstIP):
		stringVariable += srcIP + ":"
		stringVariable += str(srcPORT) + ":"
		stringVariable += dstIP + ":"
		stringVariable += str(dstPORT)
	elif(dstIP < srcIP):
		stringVariable += dstIP + ":"
		stringVariable += str(dstPORT) + ":"
		stringVariable += srcIP + ":"
		stringVariable += str(srcPORT)
	return stringVariable

# Info from CAP file
def analyse(filename):
	connection = {}
	count = 0
	
	# Connex means connections
	completeConnexCount = 0
	resetConnexCount = 0
	
	# Durations for complete connections	
	minDuration = 9999999.0
	meanDuration = 0.0
	maxDuration = 0.0
	totalDuration = 0.0

	# Round Trip Time for complete connections
	minRTT = 9999999.0
	meanRTT = 0.0
	maxRTT = 0.0
	totalRTT = 0.0
	RTTcount = 1

	# Packet Analytics
	minPackets = 9999999
	meanPackets = 0
	maxPackets = 0
	totalPackets = 0

	# Receive Window Analytics
	minWin = 9999999.0
	meanWin = 0.0
	maxWin = 0.0
	totalWin = 0.0
	WinCount = 0

	f = open(filename, 'r+b')
	pcap = dpkt.pcap.Reader(f)

	# Iterate through network layers; access each packet
	for ts,buf in pcap:
		# parse, decode into objects
		ether = dpkt.ethernet.Ethernet(buf)
		
		IP = ether.data
		TCP = IP.data

		# inet_ntoa converts IPv4 to ASCII
		srcIP = socket.inet_ntoa(IP.src)
		srcPORT = TCP.sport
		
		dstIP = socket.inet_ntoa(IP.dst)
		dstPORT = TCP.dport

		flags = TCP.flags
		sequence = TCP.seq
		acknowledge = TCP.ack
		window = TCP.win
		byteCount = len(TCP.data)

		# Connection data obtained for packets
		cData = {'ts': ts, 'srcIP': srcIP, 'srcPORT': srcPORT, 'dstIP': dstIP, 'dstPORT': dstPORT, 'flags': flags, 'sequence': sequence, 'acknowledge': acknowledge, 'window': window, 'byteCount': byteCount}
		stringVariable = stringify(srcIP, srcPORT, dstIP, dstPORT)

		# Sort packets into lists of packets
		if(stringVariable not in connection):
			connection[stringVariable] = []
		else:
			connection[stringVariable].append(cData)

		connectionCount = len(connection)

	# Loop through each packet in connection and analyse
	for stringVariable,packets in connection.items():
		count += 1
		print("\n---------------Connection # " + str(count) + "---------------")
		
		synCount = 0
		finCount = 0
		rstCount = 0

		for packet in packets:
			flags = packet['flags']
			synFlag = (flags & dpkt.tcp.TH_SYN) != 0
			finFlag = (flags & dpkt.tcp.TH_FIN) != 0
			ackFlag = (flags & dpkt.tcp.TH_ACK) != 0
			rstFlag = (flags & dpkt.tcp.TH_RST) != 0

			if(synFlag):
				synCount += 1
			if(finFlag):
				finCount += 1
			if(rstFlag):
				rstCount += 1

		RST = ""
		if(rstCount > 0):
			RST = ""
			resetConnexCount += 1
		print("Connection State: ", "S", synCount, "F", finCount, RST)

		completeConnexCount = (synCount > 0 and finCount > 0)
		if completeConnexCount:
			print("Connection complete")
			completeConnexCount += 1
		else:
			print("Connection is not complete")
			continue

		synFirst = 0
		for i in range(0, len(packets)):
			packet = packets[i]
			flags = packet['flags']
			synFlag = (flags & dpkt.tcp.TH_SYN) != 0

			if(synFlag):
				synFirst = i
				break

		finLast = -1
		for i in reversed(range(0, len(packets))):
			packet = packets[i]
			flags = packet['flags']
			finFlag = (flags & dpkt.tcp.TH_FIN) != 0

			if(finFlag):
				finLast = i
				break

		start = packets[synFirst]['ts']
		end = packets[finLast]['ts']
		duration = end - start

		print("Start time: ", datetime.datetime.utcfromtimestamp(start))
		print("End time: ", datetime.datetime.utcfromtimestamp(end))
		print("Duration: ", duration, "s")

		minDuration = min(duration, minDuration)
		maxDuration = max(duration, maxDuration)
		totalDuration += duration

		sourceIP = packets[0]['srcIP']
		sourcePORT = packets[0]['srcPORT']
		destinationIP = packets[0]['dstIP']
		destinationPORT = packets[0]['dstPORT']

		packetCount = len(packets)
		minPackets = min(minPackets, packetCount)
		maxPackets = max(maxPackets, packetCount)
		totalPackets += packetCount

		# Number of packets in each direction
		sourceCount = 0
		sourceBytes = 0
		destinationBytes = 0

		for packet in packets:
			if packet['srcIP'] == sourceIP:
				sourceCount += 1
				sourceBytes += packet['byteCount']
			else:
				destinationBytes += packet['byteCount']
		destinationCount = packetCount - sourceCount

		print("Packets sent from: ", str(sourceIP) + ":" + str(sourcePORT) + "  to  " + str(destinationPORT) + ":" + str(destinationPORT) + ":" + str(sourceCount))
		print("Packets sent from: ", str(destinationIP) + ":" + str(destinationPORT) + "  to  " + str(sourcePORT) + ":" + str(sourcePORT) + ":" + str(destinationCount))
		print("Total number of packets: ", packetCount)
		print("Data bytes sent from: ", str(sourceIP) + ":" + str(sourcePORT) + "  to  " + str(destinationIP) + ":" + str(destinationPORT) + ":" + str(sourceBytes))
		print("Data bytes sent from: ", str(destinationIP) + ":" + str(destinationPORT) + "  to  " + str(sourceIP) + ":" + str(sourcePORT) + ":" + str(destinationBytes))
		print("Total number of data bytes: ", sourceBytes + destinationBytes)

		# Acknowledgement to ts
		openPackets = {}
		for packet in packets:
			sequence = packet['sequence']
			acknowledge = packet['acknowledge']
			byteCount = packet['byteCount']
			ts = packet['ts']
			openPackets[sequence + byteCount] = ts

			if acknowledge in packets:
				RTT = ts - openPackets[acknowledge]
				RTTcount += 1
				totalRTT += RTT
				minRTT = min(minRTT, RTT)
				maxRTT = max(maxRTT, RTT)
				del openPackets[acknowledge]

		for packet in packets:
			window = packet['window']
			WinCount += 1
			totalWin += window
			minWin = min(window, minWin)
			maxWin = max(window, maxWin)

	print("\n-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-\n")
	print("Total number of connections: ", connectionCount)
	print("Number of complete connections: ", completeConnexCount)
	print("Number of reset connections: ", resetConnexCount)
	print("Number of connections still open: ", connectionCount - completeConnexCount)

	print("Min time open for complete connection: ", minDuration)
	meanDuration = totalDuration / completeConnexCount
	print("Mean time open for complete connection: ", meanDuration)
	print("Max time open for complete connection: ", maxDuration)
    
	print("Min Round Trip Time: ", minRTT)
	meanRTT = totalRTT / RTTcount
	print("Mean Round Trip Time: ", meanRTT)
	print("Max Round Trip Time: ", maxRTT)
	
	print("Min packet count for complete connection: ", minPackets)
	meanPackets = totalPackets / completeConnexCount
	print("Mean packet count for complete connection: ", meanPackets)
	print("Max packet count for complete connection: ", maxPackets)

	print("Min received window size: ", minWin)
	meanWin = totalWin / WinCount
	print("Mean received window size: ", meanWin)
	print("Max received window size: ", maxWin)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Read and analyse TCP Traffic Connections')
	parser.add_argument('filename')
	args = parser.parse_args()
	filename = args.filename

	analyse(filename)