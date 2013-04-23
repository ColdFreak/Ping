/* 
 * not using signal mechenism anymore, import "internal" parameter to measure packet sending timeing
 * send packet every 300ms, packet timeout 500ms
 * 
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

#define BUFSIZE	1500

char *host;
int sockfd;
pid_t pid;
int datalen = 56;
char recvbuf[BUFSIZE];
/*localhost dotted format address */
char h[128];
int nsent = 0;
int num_sent = 0; /* send up to 3 times*/
/* 300msごとにpacketを送る */
long interval = 300;

struct addrinfo hints;
struct addrinfo *res;
/* remote host address struct */
struct sockaddr *sasend;
struct sockaddr *sarecv;
struct timeval current_time;
struct timeval last_send_time;

uint16_t in_cksum(uint16_t *addr, int len);
//void sig_alrm(int signo);
void send_v4(void);
void readloop(void);
void tv_sub(struct timeval *out, struct timeval *in);
void proc_v4 (char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv);
int wait_for_reply(long wait_time);
int recving_time(int sockfd, char *buf, int len, struct sockaddr *response, long timeout);

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

//	signal(SIGALRM, sig_alrm); 

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

	if(gettimeofday(&current_time,0) < 0) {
		perror("gettimeofday error");
		exit(1);
	}
	last_send_time.tv_sec = current_time.tv_sec -10000;

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
	char sendbuf[BUFSIZE];
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
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;
	/*packetが戻ってきた時間を記録*/
	struct timeval tval;
	/* packetを送る間隔を計算するため */
	long lt;
	

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
//	sig_alrm(SIGALRM); /* send the first packet */
	lt = time_diff(&current_time, &last_send_time);
	if(lt < interval) goto wait_for_reply;
	


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

wait_for_reply:



}


/*
void sig_alrm(int signo) {
	if(num_sent >= 3) 
		exit(0);
	num_sent++;
	send_v4();
	ualarm(500000, 0);
	return ;
	
}
*/



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

	result = recving_time(sockfd,recvbuf,sizeof(recvbuf),&sarecv, wait_time);
	/* select() function in recving_time timeout */
	if(result < 0)
		return 0;
}

int recving_time(int sockfd, char *buf, int len, struct sockaddr *response, long timeout) {
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
		to.tv_usec = timeout % 1000
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


