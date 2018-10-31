# streamsearcher
Searches PCAP streams for content and outputting related streams in new PCAP file

## Usage
streamsearcher.py -i <input pcap> -o <output pcap> -s <string>

### What can i use this for?
This tool can be used to search for spesific patterns in a pcap to sift large pcaps into only the interesting content, including full stream context.

### Why is it so slow?
Because scapy is not the fastest packet library and by using `PcapReader` instead of `rdpcap` we avoid stuffing the whole pcap into memory, but instead suffer the consequences of more disk usage and processing.

