---
layout: post
title: Introduction to Networks
related_posts:
  - notes/_posts/2024-06-27-manageSecurityRisks.md
sitemap: false
categories: notes
---

# Introduction to Networks

* toc
{:toc}

## The TCP/IP model
The TCP/IP model is a framework used to visualize how data is organized and transmitted across a network. This model helps network engineers and network security analysts conceptualize processes on the network and communicate where disruptions or security threats occur. 

The TCP/IP model has four layers: the network access layer, internet layer, transport layer, and application layer. When troubleshooting issues on the network, security professionals can analyze which layers were impacted by an attack based on what processes were involved in an incident. 

![image](/assets/img/notes/tcp.png)

## Network access layer 
The network access layer, sometimes called the data link layer, deals with the creation of data packets and their transmission across a network. This layer corresponds to the physical hardware involved in network transmission. Hubs, modems, cables, and wiring are all considered part of this layer. The address resolution protocol (ARP) is part of the network access layer. Since MAC addresses are used to identify hosts on the same physical network, ARP is needed to map IP addresses to MAC addresses for local network communication.

## Internet layer
The internet layer, sometimes referred to as the network layer, is responsible for ensuring the delivery to the destination host, which potentially resides on a different network. It ensures IP addresses are attached to data packets to indicate the location of the sender and receiver. The internet layer also determines which protocol is responsible for delivering the data packets and ensures the delivery to the destination host. Here are some of the common protocols that operate at the internet layer:

Internet Protocol (IP). IP sends the data packets to the correct destination and relies on the Transmission Control Protocol/User Datagram Protocol (TCP/UDP) to deliver them to the corresponding service. IP packets allow communication between two networks. They are routed from the sending network to the receiving network. TCP in particular retransmits any data that is lost or corrupt.

Internet Control Message Protocol (ICMP). The ICMP shares error information and status updates of data packets. This is useful for detecting and troubleshooting network errors. The ICMP reports information about packets that were dropped or that disappeared in transit, issues with network connectivity, and packets redirected to other routers.

## Transport layer
The transport layer is responsible for delivering data between two systems or networks and includes protocols to control the flow of traffic across a network. TCP and UDP are the two transport protocols that occur at this layer. 

### Transmission Control Protocol 
The Transmission Control Protocol (TCP) is an internet communication protocol that allows two devices to form a connection and stream data. It ensures that data is reliably transmitted to the destination service. TCP contains the port number of the intended destination service, which resides in the TCP header of a TCP/IP packet.

### User Datagram Protocol 
The User Datagram Protocol (UDP) is a connectionless protocol that does not establish a connection between devices before transmissions. It is used by applications that are not concerned with the reliability of the transmission. Data sent over UDP is not tracked as extensively as data sent using TCP. Because UDP does not establish network connections, it is used mostly for performance sensitive applications that operate in real time, such as video streaming.

## Application layer
The application layer in the TCP/IP model is similar to the application, presentation, and session layers of the OSI model. The application layer is responsible for making network requests or responding to requests. This layer defines which internet services and applications any user can access. Protocols in the application layer determine how the data packets will interact with receiving devices. Some common protocols used on this layer are: 

* Hypertext transfer protocol (HTTP)

* Simple mail transfer protocol (SMTP)

* Secure shell (SSH)

* File transfer protocol (FTP)

* Domain name system (DNS)

Application layer protocols rely on underlying layers to transfer the data across the network.

![image](/assets/img/notes/osimodel.png)


## Operations at the network layer
Functions at the network layer organize the addressing and delivery of data packets across the network from the host device to the destination device. This includes directing the packets from one router to another router across the internet, till it reaches the internet protocol (IP) address of the destination network. The destination IP address is contained within the header of each data packet. This address will be stored for future routing purposes in  routing tables along the packet’s path to its destination.

All data packets include an IP address. A data packet is also referred to as an IP packet for TCP connections or a datagram for UDP connections. A router uses the IP address to route packets from network to network based on information contained in the IP header of a data packet. Header information communicates more than just the address of the destination. It also includes information such as the source IP address, the size of the packet, and which protocol will be used for the data portion of the packet. 

![image](/assets/img/notes/ipv4.png)

An IPv4 header format is determined by the IPv4 protocol and includes the IP routing information that devices use to direct the packet. The size of the IPv4 header ranges from 20 to 60 bytes. The first 20 bytes are a fixed set of information containing data such as the source and destination IP address, header length, and total length of the packet. The last set of bytes can range from 0 to 40 and consists of the options field.

The length of the data section of an IPv4 packet can vary greatly in size. However, the maximum possible size of an IPv4 packet is 65,535 bytes. It contains the message being transferred over the internet, like website information or email text. 


![image](/assets/img/notes/ipv4Packet.png)


There are 13 fields within the header of an IPv4 packet:

* **Version (VER):** This 4 bit component tells receiving devices what protocol the packet is using. The packet used in the illustration above is an IPv4 packet.

* **IP Header Length (HLEN or IHL):** HLEN is the packet’s header length. This value indicates where the packet header ends and the data segment begins. 

* **Type of Service (ToS):** Routers prioritize packets for delivery to maintain quality of service on the network. The ToS field provides the router with this information.

* **Total Length:** This field communicates the total length of the entire IP packet, including the header and data. The maximum size of an IPv4 packet is 65,535 bytes.

* **Identification:** IPv4 packets can be up to 65, 535 bytes, but most networks have a smaller limit. In these cases, the packets are divided, or fragmented, into smaller IP packets. The identification field provides a unique identifier for all the fragments of the original IP packet so that they can be reassembled once they reach their destination.

* **Flags:** This field provides the routing device with more information about whether the original packet has been fragmented and if there are more fragments in transit.

* **Fragmentation Offset:** The fragment offset field tells routing devices where in the original packet the fragment belongs.

* **Time to Live (TTL):** TTL prevents data packets from being forwarded by routers indefinitely. It contains a counter that is set by the source. The counter is decremented by one as it passes through each router along its path. When the TTL counter reaches zero, the router currently holding the packet will discard the packet and return an ICMP Time Exceeded error message to the sender. 

* **Protocol:** The protocol field tells the receiving device which protocol will be used for the data portion of the packet.

* **Header Checksum:** The header checksum field contains a checksum that can be used to detect corruption of the IP header in transit. Corrupted packets are discarded.

* **Source IP Address:** The source IP address is the IPv4 address of the sending device.

* **Destination IP Address:** The destination IP address is the IPv4 address of the destination device.

* **Options:** The options field allows for security options to be applied to the packet if the HLEN value is greater than five. The field communicates these options to the routing devices.

# Virtual networks and privacy

## Common network protocols  
Network protocols are used to direct traffic to the correct device and service depending on the kind of communication being performed by the devices on the network. Protocols are the rules used by all network devices that provide a mutually agreed upon foundation for how to transfer data across a network.

There are three main categories of network protocols: communication protocols, management protocols, and security protocols. 

* Communication protocols are used to establish connections between servers. Examples include TCP, UDP, and Simple Mail Transfer Protocol (SMTP), which provides a framework for email communication. 

* Management protocols are used to troubleshoot network issues. One example is the Internet Control Message Protocol (ICMP).

* Security protocols provide encryption for data in transit. Examples include IPSec and SSL/TLS.

Some other commonly used protocols are:

* HyperText Transfer Protocol (HTTP). HTTP is an application layer communication protocol. This allows the browser and the web server to communicate with one another. 

* Domain Name System (DNS). DNS is an application layer protocol that translates, or maps, host names to IP addresses.

* Address Resolution Protocol (ARP). ARP is a network layer communication protocol that maps IP addresses to physical machines or a MAC address recognized on the local area network.

## Wi-Fi
This section of the course also introduced various wireless security protocols, including WEP, WPA, WPA2, and WPA3. WPA3 encrypts traffic with the Advanced Encryption Standard (AES) cipher as it travels from your device to the wireless access point. WPA2 and WPA3 offer two modes: personal and enterprise. Personal mode is best suited for home networks while enterprise mode is generally utilized for business networks and applications.

## Network security tools and practices  
### Firewalls 
Previously, you learned that firewalls are network virtual appliances (NVAs) or hardware devices that inspect and can filter network traffic before it’s permitted to enter the private network. Traditional firewalls are configured with rules that tell it what types of data packets are allowed based on the port number and IP address of the data packet. 

There are two main categories of firewalls.

* **Stateless:** A class of firewall that operates based on predefined rules and does not keep track of information from data packets

* **Stateful:** A class of firewall that keeps track of information passing through it and proactively filters out threats. Unlike stateless firewalls, which require rules to be configured in two directions, a stateful firewall only requires a rule in one direction. This is because it uses a "state table" to track connections, so it can match return traffic to an existing session 

Next generation firewalls (NGFWs) are the most technologically advanced firewall protection. They exceed the security offered by stateful firewalls because they include deep packet inspection (a kind of packet sniffing that examines data packets and takes actions if threats exist) and intrusion prevention features that detect security threats and notify firewall administrators. NGFWs can inspect traffic at the application layer of the TCP/IP model and are typically application aware. Unlike traditional firewalls that block traffic based on IP address and ports, NGFWs rules can be configured to block or allow traffic based on the application. Some NGFWs have additional features like Malware Sandboxing, Network Anti-Virus, and URL and DNS Filtering.  

### Proxy servers 
A proxy server is another way to add security to your private network. Proxy servers utilize network address translation (NAT) to serve as a barrier between clients on the network and external threats. Forward proxies handle queries from internal clients when they access resources external to the network. Reverse proxies function opposite of forward proxies; they handle requests from external systems to services on the internal network. Some proxy servers can also be configured with rules, like a firewall.  For example, you can create filters to block websites identified as containing malware.

### Virtual Private Networks (VPN)
A VPN is a service that encrypts data in transit and disguises your IP address. VPNs use a process called encapsulation. Encapsulation wraps your unencrypted data in an encrypted data packet, which allows your data to be sent across the public network while remaining anonymous. Enterprises and other organizations use VPNs to help protect communications from users’ devices to corporate resources. Some of these resources include servers or virtual machines that host business applications. Individuals also use VPNs to increase personal privacy. VPNs protect user privacy by concealing personal information, including IP addresses, from external servers. A reputable VPN also minimizes its own access to user internet activity by using strong encryption and other security measures. Organizations are increasingly using a combination of VPN and SD-WAN capabilities to secure their networks. A software-defined wide area network (SD-WAN) is a virtual WAN service that allows organizations to securely connect users to applications across multiple locations and over large geographical distances. 

## Network Hardening

|Devices / Tools|Advantages|Disadvantages|
|----------------|----------|--------------|
|Firewall|A firewall allows or blocks traffic based on a set of rules.|A firewall is only able to filter packets based on information provided in the header of the packets.| 
|Intrusion Detection System (IDS)|An IDS detects and alerts admins about possible intrusions, attacks, and other malicious traffic.|An IDS can only scan for known attacks or obvious anomalies; new and sophisticated attacks might not be caught. It doesn’t actually stop the incoming traffic.|
|Intrusion Prevention System (IPS)|An IPS monitors system activity for intrusions and anomalies and takes action to stop them.|An IPS is an inline appliance. If it fails, the connection between the private network and the internet breaks. It might detect false positives and block legitimate traffic.|
|Security Information and Event Management (SIEM)|A SIEM tool collects and analyzes log data from multiple network machines. It aggregates security events for monitoring in a central dashboard.|A SIEM tool only reports on possible security issues. It does not take any actions to stop or prevent suspicious events.| 

# Glossary

## A
* Active packet sniffing: A type of attack where data packets are manipulated in transit
* Address Resolution Protocol (ARP): Used to determine the MAC address of the next router or device to traverse
## B
* Bandwidth: The maximum data transmission capacity over a network, measured by bits per second
* Baseline configuration: A documented set of specifications within a system that is used as a basis for future builds, releases, and updates
* Bluetooth: Used for wireless communication with nearby physical devices
* Botnet: A collection of computers infected by malware that are under the control of a single threat actor, known as the “bot herder"
## C
* Cloud-based firewalls: Software firewalls that are hosted by the cloud service provider
* Cloud computing: The practice of using remote servers, application, and network services that are hosted on the internet instead of on local physical devices
* Cloud network: A collection of servers or computers that stores resources and data in remote data centers that can be accessed via the internet
* Controlled zone: A subnet that protects the internal network from the uncontrolled zone
## D
* Data packet: A basic unit of information that travels from one device to another within a network
* Denial of service (DoS) attack: An attack that targets a network or server and floods it with network traffic
* Distributed denial of service (DDoS) attack: A type of denial of service attack that uses multiple devices or servers located in different locations to flood the target network with unwanted traffic
* Domain Name System (DNS): A networking protocol that translates internet domain names into IP addresses
## E
* Encapsulation: A process performed by a VPN service that protects your data by wrapping sensitive data in other data packets
## F
* File Transfer Protocol (FTP): Used to transfer files from one device to another over a network
* Firewall: A network security device that monitors traffic to or from your network
* Forward proxy server: A server that regulates and restricts a person’s access to the internet
## H
* Hardware: The physical components of a computer
* Hub: A network device that broadcasts information to every device on the network
* Hypertext Transfer Protocol (HTTP): An application layer protocol that provides a method of communication between clients and website servers
* Hypertext Transfer Protocol Secure (HTTPS): A network protocol that provides a secure method of communication between clients and servers
## I
* Identity and access management (IAM): A collection of processes and technologies that helps organizations manage digital identities in their environment
* IEEE 802.11 (Wi-Fi): A set of standards that define communication for wireless LANs
* Internet Control Message Protocol (ICMP): An internet protocol used by devices to tell each other about data transmission errors across the network
* Internet Control Message Protocol (ICMP) flood: A type of DoS attack performed by an attacker repeatedly sending ICMP request packets to a network server
* Internet Protocol (IP): A set of standards used for routing and addressing data packets as they travel between devices on a network
* Internet Protocol (IP) address: A unique string of characters that identifies the location of a device on the internet
* IP spoofing: A network attack performed when an attacker changes the source IP of a data packet to impersonate an authorized system and gain access to a network
## L
* Local area network (LAN): A network that spans small areas like an office building, a school, or a home
## M
* Media Access Control (MAC) address: A unique alphanumeric identifier that is assigned to each physical device on a network
* Modem: A device that connects your router to the internet and brings internet access
to the LAN
* Multi-factor authentication (MFA): A security measure that requires a user to verify their identity in two or more ways to access a system or network
## N
* Network: A group of connected devices
* Network log analysis: The process of examining network logs to identify events of interest
* Network protocols: A set of rules used by two or more devices on a network to describe the order of delivery of data and the structure of data
* Network segmentation: A security technique that divides the network into segments
## O
* Operating system (OS): The interface between computer hardware and the user
* Open systems interconnection (OSI) model: A standardized concept that describes the seven layers computers use to communicate and send data over the network
* On-path attack: An attack where a malicious actor places themselves in the middle of an authorized connection and intercepts or alters the data in transit
## P
* Packet sniffing: The practice of capturing and inspecting data packets across a network
* Passive packet sniffing: A type of attack where a malicious actor connects to a network hub and looks at all traffic on the network
* Patch update: A software and operating system update that addresses security vulnerabilities within a program or product

* Penetration testing: A simulated attack that helps identify vulnerabilities in systems, networks, websites, applications, and processes
* Ping of death: A type of DoS attack caused when a hacker pings a system by sending it an oversized ICMP packet that is bigger than 64KB
* Port: A software-based location that organizes the sending and receiving of data between devices on a network
* Port filtering: A firewall function that blocks or allows certain port numbers to limit unwanted communication
* Proxy server: A server that fulfills the requests of its clients by forwarding them to other servers
## R
* Replay attack: A network attack performed when a malicious actor intercepts a data packet in transit and delays it or repeats it at another time
* Reverse proxy server: A server that regulates and restricts the Internet's access to an internal server
* Router: A network device that connects multiple networks together
## S
* Secure File Transfer Protocol (SFTP): A secure protocol used to transfer files from one device to another over a network
* Secure shell (SSH): A security protocol used to create a shell with a remote system
* Security hardening: The process of strengthening a system to reduce its vulnerabilities and attack surface
* Security information and event management (SIEM): An application that collects and analyzes log data to monitor critical activities for an organization
* Security zone: A segment of a company’s network that protects the internal network from the internet
* Simple Network Management Protocol (SNMP): A network protocol used for monitoring and managing devices on a network
* Smurf attack: A network attack performed when an attacker sniffs an authorized user’s IP address and floods it with ICMP packets
* Speed: The rate at which a device sends and receives data, measured by bits per second
* Stateful: A class of firewall that keeps track of information passing through it and proactively filters out threats
* Stateless: A class of firewall that operates based on predefined rules and that does not keep track of information from data packets
* Subnetting: The subdivision of a network into logical groups called subnets
* Switch: A device that makes connections between specific devices on a network by sending and receiving data between them
* Synchronize (SYN) flood attack: A type of DoS attack that simulates a TCP/IP connection and floods a server with SYN packets
## T
* TCP/IP model: A framework used to visualize how data is organized and transmitted across a network
* Transmission Control Protocol (TCP): An internet communication protocol that allows two devices to form a connection and stream data
* Transmission control protocol (TCP) 3-way handshake: A three-step process used to establish an authenticated connection between two devices on a network
## U
* Uncontrolled zone: The portion of the network outside the organization
* User Datagram Protocol (UDP): A connectionless protocol that does not establish a connection between devices before transmissions

## V
* Virtual Private Network (VPN): A network security service that changes your public IP address and masks your virtual location so that you can keep your data private when you are using a public network like the internet
## W
* Wide Area Network (WAN): A network that spans a large geographic area like a city, state, or country
* Wi-Fi Protected Access (WPA): A wireless security protocol for devices to connect to the internet