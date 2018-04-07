# SlowPostDDoSDetector

Slow POST is an attack that attackers can utilize all server resources by using a single computer. This attack consumes server resources by creating different HTTP connections from different source ports concurrently and keeping the connections alive for a very long time by sending small amount of data at a regular interval. In order to perform a successful HTTP flood, attackers send enormous numbers of requests to utilize the server resources from different IP addresses. Just because each request must complete TCP handshake correctly, attackers need to have a botnet like environment to flood server resources.

In addition to that, since this is an Application Layer (Layer 7) attack and TCP packages are completely legal it is very hard or impossible to detect Slow POST attack by Layer 4 DDoS protection solutions.

This is python script to detect Slow Post DDoS Attacks. It parses the pcap file and tries to detect the attack by using the threshold values below and prints the attack parameters.
* Number of concurrent connections
* Max interval between sending two segments of data
* Minimum size of segments in bytes

## Usage

```slow_post_detector.py -f FILE_TO_PARSE -c NUMBER_OF_CONNS -i MAX_INTERVAL_IN_SECONDS -s MIN_TCP_SEGMENT_SIZE_IN_BYTES```

## Example

```# slow_post_detector.py -f capture.pcap -c 5 -i 4 -s 100```

output:
```Slow POST Attack is detected which is targeting 192.168.2.2:80
There are 100 suspicious connections
 - Average packet length: 15 bytes 
 - Average time interval between two payloads: 5.0 seconds
```
