// Test
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    int res;
    const u_char *pkt_data;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    u_char buffer[9000];

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("Device is %s\n", dev);
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while((res = pcap_next_ex( handle, &header, &pkt_data)) >= 0){

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        printf("================================================\n");
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
        // Source Mac Address
        printf("eth.smac: ");
        for(int i=6; i<12; i++)
        {
            printf("%02x", *(pkt_data+i));
            if(i!=11)printf(":");
        }
        printf("\n");
        // Destination Mac Address
        printf("eth.dmac: ");
        for(int i=0; i<6; i++)
        {
            printf("%02x", *(pkt_data+i));
            if(i!=5)printf(":");
        }
        printf("\n");
        // Check IPv4
        if(*(pkt_data+12) == 0x08 && *(pkt_data+13) == 0x00)
            printf("----------------------IPv4----------------------\n");
        else continue;
        // Source IP
        printf("ip.sip: ");
        for(int i=26; i<30; i++)
        {
            printf("%d", *(pkt_data+i));
            if(i!=29)printf(".");
        }
        printf("\n");
        // Destination IP
        printf("ip.dip: ");
        for(int i=30; i<34; i++)
        {
            printf("%d", *(pkt_data+i));
            if(i!=33)printf(".");
        }
        printf("\n");
        // Check TCP
        if(*(pkt_data+23) == 0x06)
            printf("----------------------TCP-----------------------\n");
        else continue;
        // TCP Source Port
        char temp[10];
        long n;
        sprintf(temp, "%s%02x%02x","0x", *(pkt_data+34), *(pkt_data+35));
        n = strtol(temp, NULL, 16);
        printf("tcp.sport: %d\n",n);
        // TCP Destination Port
        char temp2[10];
        sprintf(temp2, "%s%02x%02x","0x", *(pkt_data+36), *(pkt_data+37));
        n = strtol(temp2, NULL, 16);
        printf("tcp.dport: %d\n",n);
        // Display Data
        printf("---------------------Data-----------------------\n");
        printf("                  ");
        char temp3[10];
        sprintf(temp3, "%s%02x","0x",*(pkt_data+46));
        for(int i=34+((int)strtol(temp3,NULL,16)/4);i<header->len;i++)
            {
            printf("%02x ", *(pkt_data+i));
            if((i+1)%8==0) printf(" ");
            if((i+1)%16==0) printf("\n");
        }
        printf("\n");
    }
    return(0);
}
