/*
 * send SYN packet
 */
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h> /* bzero() */
#include <string.h>
#include <arpa/inet.h> /* inet_ntop()*/
#include <netinet/ip_icmp.h> /* struct icmp */
#include <sys/time.h>
#include <netinet/in.h> /* struct sockaddr_in */
#include <unistd.h> /* ualarm()*/
#include <pcap.h>

#define BUFSIZE	1500
int src_port = 5555;

#define ETHERNET_SIZE 14
#define ETHER_ADDR_LEN	6
struct ethernetheader {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct ipheader {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
   	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct tcpheader {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	u_int th_seq;                 /* sequence number */
	u_int th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

struct pseudo_hdr {
	unsigned int src;          /* 32bit source ip address*/
	unsigned int dst;          /* 32bit destination ip address */	
	unsigned char mbz;             /* 8 reserved bits (all 0) 	*/
	unsigned char proto;           /* protocol field of ip header */
	unsigned short len;          /* tcp length (both header and data */
};

char *host;
int sockfd;
pid_t pid;
int datalen = 56;
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

// get local ipaddress using findalldevs() function
char local_ip[20]; 
//remote ip  dotted format address
char remote_ip[20];

int nsent = 0;

struct addrinfo hints;
struct addrinfo *res;
struct sockaddr local; // localhost sockaddr struture
struct sockaddr *lh; // localhost
struct sockaddr *sasend; /* remote host address struct */
struct sockaddr *sarecv;
/*packetが戻ってきた時間を記録*/
struct timeval tvrecv;

uint16_t in_cksum(uint16_t *addr, int len);
//void sig_alrm(int signo);
void send_v4(void);
void readloop(void);
void tv_sub(struct timeval *out, struct timeval *in);
void proc_v4 (char *ptr, ssize_t len, struct timeval *tvrecv);
int wait_for_reply(long wait_time);
int recving_time(int sockfd, char *buf, int len, struct sockaddr *response, long timeout);
void *get_local_ip(struct sockaddr *local);

int main(int argc, char **argv) {
	struct sockaddr_in *remote_host;
	socklen_t salen;
	int n; /* getaddrinfo return value */
	char *buffer;

	if(argc != 2) {
		perror("usage: ./ping <hostname>");
		exit (1);
	}
	/*
	 	struct sockaddr {
			unsigned short sa_family;
			char sa_data[14];
		}
	 */
	get_local_ip(&local);
	lh = &local;

	host = argv[1];
	pid = getpid() & 0xffff;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	if( ( n = getaddrinfo(host, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(n));
		exit (1);
	}

	sasend = res->ai_addr;
	switch (sasend->sa_family) {
		case AF_INET:
			if(inet_ntop(AF_INET,&(((struct sockaddr_in*)sasend)->sin_addr), remote_ip, 128) == NULL) {
				perror("inet_ntop");
				exit (1);
			}
			break;

		default:
			perror("Not IPv4 address");
			exit (1);
	}


	printf("PING %s (%s): %d data bytes\n",res->ai_canonname ? res->ai_canonname:remote_ip, remote_ip, datalen);

	readloop();
	return 0;
}

void send_v4(void) {
	struct ipheader *iph;
	struct tcpheader *tcph;
	struct pseudo_hdr *phdr;
	struct in_addr remote;

	int len;
	socklen_t salen;
	iph = (struct ipheader *)sendbuf;
	tcph = (struct tcpheader *)(sendbuf+sizeof(struct ipheader));
	phdr = (struct pseudo_hdr *)(sendbuf+sizeof(struct ipheader)+sizeof(struct tcpheader));

	iph->ip_vhl = 0x45; 
	iph->ip_tos = 0; /* type of service -not needed */
	iph->ip_len = sizeof(struct ipheader)+sizeof(struct tcpheader);
	iph->ip_id = pid;
	iph->ip_off = 0; /* no fragmentation */
	iph->ip_ttl = 255; 	
	iph->ip_p = IPPROTO_TCP;
	iph->ip_src = ((struct sockaddr_in*)lh)->sin_addr;
	iph->ip_dst = ((struct sockaddr_in*)sasend)->sin_addr;
	iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ipheader));
	
	tcph->th_sport=htons(++src_port); // arbitrary port 

	tcph->th_dport = htons(0);
	tcph->th_seq= random(); // random return long ?
	tcph->th_ack = 0;
	tcph->th_offx2 = 0x50; // 5 offset ( 8 0s reserved)
	tcph->th_flags = TH_SYN;
	tcph->th_win = 65535;
	tcph->th_sum = 0; // will compute later
	tcph->th_urp = 0; // no urgent pointer 
	
	/*
	 	struct sockaddr_in {
			short sin_family;
			unsigned short sin_port;
			struct in_addr sin_addr;
			char sin_zero[8];
		};

		struct in_addr {
			unsigned long s_addr;
		};
	 */
	phdr->src = ((struct sockaddr_in*)lh)->sin_addr.s_addr;
	phdr->dst = ((struct sockaddr_in*)sasend)->sin_addr.s_addr;
	phdr->mbz = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->len = ntohs(sizeof(struct tcpheader));
	
	tcph->th_sum = htons(in_cksum((unsigned short *)tcph, sizeof(struct pseudo_hdr)+sizeof(struct tcpheader)));

	sasend = res->ai_addr;
	salen = res->ai_addrlen;
	if(sendto(sockfd, sendbuf, iph->ip_len, 0, sasend,salen)  < 0) 
		fprintf(stderr, "Error sending datagram for port 0");
#ifdef DEBUG
	fprintf(stderr,"Sending the %dth packet and salen = %d\n",nsent, salen);
#endif 
	nsent++;

}
void readloop(void) {
	ssize_t n;
	int size;

	// create socket from here
	if(res->ai_family == AF_INET) {
		if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
			perror("socket");
			exit(1);
		}
	}
	else {
		fprintf(stderr,"unknown address family %d", res->ai_family);
		exit (1);
	}
	setuid(getuid());

	size = 60 * 1024;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	int one = 1;
	const int *val = &one;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		fprintf(stderr, "Warning: Cannot set HDRINCL for port 0");

    while(nsent < 4) {
        send_v4();
        wait_for_reply(1000);
    }
}



void proc_v4 (char *ptr, ssize_t len, struct timeval *tvrecv) {
	int ip_size, tcp_size;
	struct ipheader *ip;
	struct tcpheader *tcp;
	struct timeval *tvsend;
	double rtt;

	ip = (struct ipheader*)ptr;
	/* only check two fields of ip header, length and protocol */
	ip_size = IP_HL(ip) * 4; /* length of ip header */
#ifdef DEBUG
	fprintf(stderr, "ip_size = %d",ip_size);
#endif
	if(ip_size < 20) {
		fprintf(stderr, "Invalid IP header length: %d\n",ip_size);
		return ;
	}
	if(ip->ip_p != IPPROTO_TCP ) {

		fprintf(stderr,"Returned Packet is not TCP protocol\n");
		return;		/*second, check protocol */
	}
	tcp = (struct tcpheader *)(ptr + ETHERNET_SIZE + ip_size); /* start of icmp header */

#ifdef DEBUG
	fprintf(stderr, "tcp_size = %d",tcp_size);
#endif
	if(tcp_size < 20) {
		fprintf(stderr, "Invalid TCP header length: %d\n",tcp_size);
		return ;
	}

	if(((tcp->th_flags & 0x04) == TH_RST ) && (tcp->th_flags & 0x10) == TH_ACK) 
		fprintf(stdout, "RESET packet received.\n");


}

void tv_sub(struct timeval *out, struct timeval *in) {
	if((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 100000;
	}
	out->tv_sec -= in->tv_sec;
}

long time_diff(struct timeval *a, struct timeval *b) {
	long sec_diff = a->tv_sec - b->tv_sec;
	if(sec_diff == 0) 
		return (a->tv_usec - b->tv_usec);
	else if(sec_diff < 100)
		return (sec_diff * 1000 + a->tv_usec - b->tv_usec);
	else
		return (sec_diff * 1000);
}


int wait_for_reply(long wait_time) {
	/*timeout or not */
	int result;
	ssize_t n;

	result = recving_time(sockfd,recvbuf,sizeof(recvbuf),sarecv, wait_time);
	/* select() function in recving_time timeout */
	if(result < 0)
		return 0;
	n = sizeof(recvbuf);
	fprintf(stderr, "n = %d\n",n);
	proc_v4(recvbuf, n, &tvrecv);
	return 1;
}

int recving_time(int sockfd, char *buf, int len, struct sockaddr *sarecv, long timeout) {
	ssize_t n;
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;
	/* timeout structure*/
	struct timeval to;
	int readable;
	fd_set readset;

select_again:
	if(timeout < 1000) {
		to.tv_sec = 0;
		to.tv_usec = timeout;
	}
	else {
		to.tv_sec = timeout / 1000;
		to.tv_usec = timeout % 1000;
	}

	FD_ZERO(&readset);
	FD_SET(sockfd, &readset);
	readable = select(sockfd+1, &readset, NULL, NULL, &to);
#ifdef DEBUG
	fprintf(stderr, "readable is %d\n",readable);
	fprintf(stderr, "sockfd = %d\n", sockfd);
#endif
	if(readable < 0) {
		if(errno == EINTR)
			goto select_again;
		else {
			perror("select() error");
			exit(1);
		}
	}

	if(readable == 0)  {
		return -1;
	}

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;

	for(;;) {
		n = recvmsg(sockfd, &msg,0);
#ifdef DEBUG
		fprintf(stderr, "recived %d bytes\n",n);
#endif
		if( n < 0) 
			if(errno == EINTR )
				continue;
			else {
				perror("recvmsg");
				exit(1);
			}
		else
			break;
	}
	return n;
}

uint16_t in_cksum(uint16_t *addr, int len) {
	int nleft = len;
	uint32_t sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

void *get_local_ip(struct sockaddr *local) {
/*
 	struct pcap_if {
		struct pcap_if *next;
		char *name;
		char *description;
		pcap_addr *addresses;
		u_int flags;
	};

	struct pcap_addr {
		struct pcap_addr *next;
		struct sockaddr *addr;
		struct sockaddr *netmask;
		struct sockaddr *broadaddr;
		struct sockaddr *dstaddr;
	};
 */
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *a;
	char errbuf[PCAP_ERRBUF_SIZE];
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
		printf("%s\n",errbuf);
		return NULL;
    }
    for(d = alldevs; d != NULL; d= d->next) {
		for(a = d->addresses; a!= NULL; a = a->next) {
			if(a->addr->sa_family == AF_INET)  {
				memcpy(local, a->addr, sizeof(struct sockaddr));
				return;
			}
		}
    }
}
