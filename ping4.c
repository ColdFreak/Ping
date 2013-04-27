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

struct sniff_tcp {
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
	u_int32_t src;          /* 32bit source ip address*/
	u_int32_t dst;          /* 32bit destination ip address */	
	u_char mbz;             /* 8 reserved bits (all 0) 	*/
	u_char proto;           /* protocol field of ip header */
	u_int16_t len;          /* tcp length (both header and data */
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
/* remote host address struct */
struct sockaddr *sasend;
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
void *get_local_ip(char *buf);

int main(int argc, char **argv) {
	struct icmp *icmp;
	struct sockaddr_in *remote_host;
	socklen_t salen;
	int n; /* getaddrinfo return value */
	char *buffer;

	if(argc != 2) {
		perror("usage: ./ping <hostname>");
		exit (1);
	}

	host = argv[1];
	pid = getpid() & 0xffff;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	if( ( n = getaddrinfo(host, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(n));
		exit (1);
	}

	remote_host = (struct sockaddr_in *)(res->ai_addr);
	switch (remote_host->sin_family) {
		case AF_INET:
			if(inet_ntop(AF_INET,&(remote_host->sin_addr), remote_ip, 128) == NULL) {
				perror("inet_ntop");
				exit (1);
			}
			break;

		default:
			perror("Not IPv4 address");
			exit (1);
	}

	printf("PING %s (%s): %d data bytes\n",res->ai_canonname ? res->ai_canonname:h, h, datalen);

	readloop();
	return 0;
}

void send_v4(void) {
	struct ipheader *iph;
	struct tcpheader *tcph;

	int len;
	socklen_t salen;
	iph = (struct ipheader *)sendbuf;
	tcph = (struct tcpheader *)(sendbuf+sizeof(struct ipheader));

	iph->ip_vhl = 0x45; 
	iph->ip_tos = 0; /* type of service -not needed */
	iph->ip_len = sizeof(struct ipheader)+sizeof(struct tcpheader);
	iph->ip_id = htons(pid);
	iph->ip_off = 0; /* no fragmentation */
	iph->ip_ttl = 255; 	
	iph->ip_p = IPPROTO_TCP;
	iph->ip_src = inet_addr(local_ip);
	iph->ip_dst = inet_addr(remote_ip);
	iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ipheader));
	

	memset(icmp->icmp_data,0, datalen);
	if(gettimeofday((struct timeval *)icmp->icmp_data, NULL) < 0) {
		perror("gettimeofday");
		exit (1);
	}
	len = 8 + datalen;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *)icmp,len);

	sasend = res->ai_addr;
	salen = res->ai_addrlen;
	if(sendto(sockfd, sendbuf, len, 0, sasend, salen) != len) {
		perror("sendto");
		exit(1);
	}
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

    while(nsent < 4) {
        send_v4();
        if(wait_for_reply(5000)) 
	    break;

    }
}



void proc_v4 (char *ptr, ssize_t len, struct timeval *tvrecv) {
	int hlenl, icmplen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;

	ip = (struct ip*)ptr;
	/* only check two fields of ip header, length and protocol */
	hlenl = ip->ip_hl << 2; /* length of ip header */
	if(ip->ip_p != IPPROTO_ICMP )
		return;		/*second, check protocol */
	icmp = (struct icmp *)(ptr + hlenl); /* start of icmp header */
	if((icmplen = len - hlenl) < 8)
		return ;
	if(icmp->icmp_type == ICMP_ECHOREPLY) {
		if(icmp->icmp_id != pid)
			return;
		if(icmplen < 16)
			return;
		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(tvrecv,tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec/1000.0;
		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",icmplen, h, icmp->icmp_seq, ip->ip_ttl, rtt);

	}
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
	/* if error happens on select() function*/
	if(readable < 0) {
		if(errno == EINTR)
			goto select_again;
		else {
			perror("select() error");
			exit(1);
		}
	}

	/* select() returns 0 means timeout*/
	if(readable == 0)
		return -1;

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;

	for(;;) {
		n = recvmsg(sockfd, &msg,0);
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
	// write down packet recived time
	// tvrecv is a global variable
	if(gettimeofday(&tvrecv, 0) < 0) {
		perror("gettimeofday");
		exit(1);
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

void *get_local_ip(char *buf) {

    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *a;

    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
	printf("%s\n",errbuf);
	return NULL;
    }
    for(d = alldevs; d != NULL; d= d->next) {
	for(a = d->addresses; a!= NULL; a = a->next) {
    	    if(a->addr->sa_family == AF_INET)  {
		strcpy(buf, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
		return;
            }
	}
    }
}
