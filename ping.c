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

#define BUFSIZE	1500

char *host;
int sockfd;
pid_t pid;
int datalen = 56;
char sendbuf[BUFSIZE];
char h[128];
int nsent = 0;

struct addrinfo hints;
struct addrinfo *res;
struct sockaddr *sasend;
struct sockaddr *sarecv;

uint16_t in_cksum(uint16_t *addr, int len);
void sig_alrm(int signo);
void send_v4(void);
void readloop(void);
void tv_sub(struct timeval *out, struct timeval *in);
void proc_v4 (char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv);

int main(int argc, char **argv) {
	struct icmp *icmp;
	struct sockaddr_in *sin;
	socklen_t salen;
	int n; /* getaddrinfo return value */
	char *buffer;

	if(argc != 2) {
		perror("usage: ./ping <hostname>");
		exit (1);
	}

	host = argv[1];
	pid = getpid() & 0xffff;
	signal(SIGALRM, sig_alrm); 

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	if( ( n = getaddrinfo(host, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(n));
		exit (1);
	}
	
	sin = (struct sockaddr_in *)(res->ai_addr);	
	switch (sin->sin_family) {
		case AF_INET: 
			if(inet_ntop(AF_INET,&(sin->sin_addr), h, 128) == NULL) {
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
void send_v4(void) {
	struct icmp *icmp;
	int len;
	socklen_t salen;
	icmp = (struct icmp *)sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_seq = nsent++;
	icmp->icmp_id = pid;
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
	char recvbuf[BUFSIZE];
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;
	struct timeval tval;
	

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
	sig_alrm(SIGALRM); /* send the first packet */

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;

	for( ; ; ) {/* now receive message after sending packet */
		n = recvmsg(sockfd, &msg, 0);
		if( n < 0) {
			if(errno == EINTR ) 
				continue;
			else {
				perror("recvmsg");
				exit(1);
			}
		}
		if(gettimeofday(&tval, NULL) < 0) {
			perror("gettimeofday");
			exit (1);
		}
		proc_v4(recvbuf, n, &msg, &tval);
	}
}

void sig_alrm(int signo) {
	send_v4();
	alarm(1);
	return ;
}


void proc_v4 (char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv) {
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
