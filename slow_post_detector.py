#!/usr/bin/env python
import dpkt
import socket
import operator
import argparse

class SlowPostDetector:

    """

    This script tries to detect Slow POST attacks by parsing the pcap file using packet size,
    the time interval between two TCP messages and number of concurrent connections.

    File Name: slow_post_detector.py
    Python Version: 2.7
    Author: Oguzhan Topgul

    """

    def __init__(self):

        """
        Get threshold values from the user as command line arguments

        slow_post_detector.py --file FILE_TO_PARSE --concurrent-connections NUMBER_OF_CONNS --interval MAX_INTERVAL_IN_SECONDS --packet-size MIN_TCP_SEGMENT_SIZE_IN_BYTES

        --file: pcap file to parse

        --concurrent-connections: Number of concurrent connections to decide if this is a Slow POST attack

        --interval: MAximum time interval (in seconds) between two TCP segments (message bodies) to decide if this is an attack

        --packet-size: Minimum size of message bodies (in bytes) to decide if this is an attack.

        """
        parser = argparse.ArgumentParser()
        parser.add_argument('-f', '--file', dest='file', action='store', required=True)
        parser.add_argument('-c', '--concurrent-connections', dest='concurrent_connections', action='store', required=True)
        parser.add_argument('-i', '--interval', dest='max_interval', action='store', required=True)
        parser.add_argument('-s', '--packet-size', dest='min_packet_size', action='store', required=True)

        try:
            self.__args = parser.parse_args()
        except Exception:
            print "Error while parsing arguments"


    def parse_pcap_file(self):
        # Open the pcap file
        file = self.__args.file
        f = open(file)
        pcap = dpkt.pcap.Reader(f)

        #Targets dictionary holds the number of connection is established for each target
        targets = dict()

        # Paylod size dictionary holds TCP segment sizes for TCP PUSH'es
        payload_sizes = dict()

        # Intervals dictionary holds the timestamps for TCP PUSH'es.
        # [(SOURCE_IP, SOURCE_PORT, DESTINATION_IP, DESTINATION_PORT): TIMESTAMP_OF_THE_PUSH]
        intervals = dict()

        #Loop over the connections
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            # Only care about IP protocol
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data

            # Only care about TCP protocol
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data

            #Check the TCP Flags and fill the dictionaries accordingly
            if "S" == self.tcp_flags(tcp.flags):
                """
                When it is a SYN , we can parse the destination target and fill the targets dictionary.
                SYN's the initial packets from the client to the server
                """
                if (socket.inet_ntoa(ip.dst), tcp.dport) in targets:
                    targets[(socket.inet_ntoa(ip.dst), tcp.dport)] = targets[(socket.inet_ntoa(ip.dst), tcp.dport)] + 1
                else:
                    targets[(socket.inet_ntoa(ip.dst), tcp.dport)] = 1

            elif "PA" == self.tcp_flags(tcp.flags):
                """
                When it is a PUSH-ACK, fill the intervals and payload_sizes dictonaries. 
                PUSH-ACK's are the TCP packets where attackers send segmented data.
                
                """
                if (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport) in intervals:
                    intervals[(socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)].append(ts)

                    if (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport) in payload_sizes:
                        payload_sizes[(socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)].append(len(tcp.data))
                    else:
                        payload_sizes[(socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)] = [len(tcp.data)]
                else:
                    if tcp.data[:4] == "POST":
                        intervals[(socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)] = [ts]

                        if (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport) in payload_sizes:
                            payload_sizes[(socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)].append(len(tcp.data))
                        else:
                            payload_sizes[(socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)] = [len(tcp.data)]


        """ 
        PCAP is parsed, dictionaries are filled. 
        Let's do the analysis on them and decide if there is an attack
        """
        self.do_analysis(targets, intervals, payload_sizes)
        f.close()


    def do_analysis(self, targets, intervals, paylod_sizes):

        # Initialize values from command line arguments
        max_number_of_concurrent_connections = int(self.__args.concurrent_connections)
        max_interval = int(self.__args.max_interval)
        min_packet_size = int(self.__args.min_packet_size)
        # More than 10 suspicious PUSH'es, will make the connection suspicious
        request_threshold = 10

        # Let's find the main target of the attack by comparing the number of established connections for each target
        main_target = max(targets.iteritems(), key=operator.itemgetter(1))[0]


        # Store  number of suspicious connections from SOURCE_IP:SOURCE_PORT pairs
        suspicious_connections = dict()
        # If a packet is suspicious, store the packet length so we can calculate average packet length (message size)
        average_packet_lengths = dict()
        # If a packet is suspicious, store the interval between TWO packets so we can calculate average time interval
        average_intervals = dict()

        for key, value in paylod_sizes.iteritems():
            suspicious_count = 0
            sum_of_packet_lengts = 0
            sum_of_intervals = 0

            payload_sizes_array = value

            index = 0
            while index < len(payload_sizes_array):
                # If the packet size is under threshold packet size
                if payload_sizes_array[index] < min_packet_size:
                    # There is no time interval for the first packet, let's pass that
                    if index > 0:
                        diff = intervals.get(key)[index] - intervals.get(key)[index-1]
                        # Packet size is under the threshold, and if interval is also above the threshold
                        if diff > max_interval:
                            # Check if the destionation is the main target
                            if key[2] == main_target[0] and key[3] == main_target[1]:
                                suspicious_count = suspicious_count + 1
                                sum_of_packet_lengts += payload_sizes_array[index]
                                sum_of_intervals += diff
                index = index + 1
            # Check if there is enough PUSH'es above the threshold, that means this connection is suspicious
            if suspicious_count > request_threshold:
                suspicious_connections[key] = suspicious_count
                average_packet_lengths[key] = sum_of_packet_lengts / suspicious_count
                average_intervals[key] = sum_of_intervals / suspicious_count

        # Check if the number of suspicious connections above the max # of concurrent threshold limit. That means there is a Slow POST attack.
        if len(suspicious_connections) > max_number_of_concurrent_connections:
            print "\nSlow POST Attack is detected which is targeting {}:{}".format(main_target[0], main_target[1])
            print "There are {} suspicious connections\n " \
                  "- Average packet length: {} bytes \n " \
                  "- Average time interval between two payloads: {} seconds".format(len(suspicious_connections),
                                                                                    self.calculate_attack_average_packet_size(average_packet_lengths),
                                                                                    self.calculate_attack_average_interval(average_intervals))
        else:
            print "\nNo Slow POST Attack detected"


    """ Helper Functions """
    def calculate_attack_average_packet_size(self, average_packet_lengths):
        sum_of_packets_lengths = 0
        for key, value in average_packet_lengths.iteritems():
            sum_of_packets_lengths += value

        return sum_of_packets_lengths/len(average_packet_lengths)

    def calculate_attack_average_interval(self, average_intervals):
        sum_of_intervals = 0
        for key, value in average_intervals.iteritems():
            sum_of_intervals += value

        return round(sum_of_intervals/len(average_intervals))

    #Stringify TCP Flags
    def tcp_flags(self, flags):
        ret = ''
        if flags & dpkt.tcp.TH_FIN:
            ret = ret + 'F'
        if flags & dpkt.tcp.TH_SYN:
            ret = ret + 'S'
        if flags & dpkt.tcp.TH_RST:
            ret = ret + 'R'
        if flags & dpkt.tcp.TH_PUSH:
            ret = ret + 'P'
        if flags & dpkt.tcp.TH_ACK:
            ret = ret + 'A'
        if flags & dpkt.tcp.TH_URG:
            ret = ret + 'U'
        if flags & dpkt.tcp.TH_ECE:
            ret = ret + 'E'
        if flags & dpkt.tcp.TH_CWR:
            ret = ret + 'C'
        return ret
    """ End Helper Functions """

if __name__ == '__main__':
    slow_post_detector = SlowPostDetector()
    slow_post_detector.parse_pcap_file()
