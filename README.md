# Net DFIR
Perform baselining and analysis on network captures.

## Use
```bash
./netdfir.sh -r <pcap_file> -e -a
```
- -r : Specify the input PCAP file for analysis (required)
- -e : Export files detected in data streams (optional)
- -a : Specify an adversary IP address to highlight (optional)

![image](https://github.com/user-attachments/assets/6ad066dd-013d-499e-b7c4-a35a22450e25)

## Example Output

To help with the process of determining malicious traffic, adversary IP addresses and indiciators of compromise:
- All public IPs are mapped to their country of origin.
- Countries that are blacklisted are highlighted in red.
- Known malicious IP addresses are also highlighted red.  

### Active Directory
Net DFIR will attempt to pull information about the local Windows AD environment. Information regarding the DC, Windows Hosts and Windows Users will be logged along with associated IP's and MAC addresses.
Any outgoing connections will be listed with associated ports and occurences.

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/a79462cf-5018-4fe8-b543-150d0fb42ad4">

### IP Addresses
A list of all IP addresses found within the PCAP are collated and listed based on the number of occurences decending. IPs are mapped to originating country and highlighted based on blocklists and known malicious IP lists.

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/d469054f-1de5-459b-aca1-e510a0768426">

### User Agents
A list of user agents found within HTTP traffic are collated and listed based on the number of occurences decending.

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/9a1258d1-ca88-4985-b9e1-e218cca5c13c">

### Server Hosts

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/308a201e-dd97-4935-9956-b191bd2e7b11">

### Request URIs

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/c4126d17-86b4-41d1-8745-9627d0676b36">

### HTTP Objects

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/937370a8-8cf8-4a1a-86dd-c958398c90f4">

### SMB Objects

<img height="auto" width="600px" src="https://github.com/user-attachments/assets/976437f0-2e37-40ad-9aae-dabbf7855227">
