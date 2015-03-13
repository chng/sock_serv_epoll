#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <errno.h>

#define NDEBUG

//#define TRACE(X) {printf(#X"\n"); X;}
#ifndef TRACE
#define TRACE(X) X;
#endif

#ifndef MAXEVENTS
#define MAXEVENTS 64
#endif
#ifndef TX_BUF_SIZE
#define TX_BUF_SIZE (65535)
#endif
#ifndef RX_BUF_SIZE
#define RX_BUF_SIZE (65535)
#endif

char buf[RX_BUF_SIZE];

void user_recv_handler(int efd, int fd, char * buf, int len)
{
	//do simething weith buf and fd.
	//do nothing but register a sending event
	// epoll will send the content in buf[] through out ev.data.fd
	int s = -1;
	struct epoll_event ev;
	ev.data.fd = fd;
	ev.events = EPOLLOUT | EPOLLET;
	s = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	//assert(s!=-1);
	if(s==-1)
	{
		fprintf(stderr, "epoll out error.\n");
		return;
	}
}

struct addrinfo* tcpipv4_getaddrinfo(char* port)
{
	struct addrinfo hints;
	struct addrinfo *res;
	int s;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET; // ipv4 addrs 
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, port, &hints, &res);
	//assert(s==0);
	if (s)
	{
		fprintf(stderr, "failed to getaddrinfo: %s\n", gai_strerror(s));
		return NULL;
	}
	return res;
}


struct addrinfo* tcpipv6_getaddrinfo(char* port)
{
	struct addrinfo hints;
	struct addrinfo *res;
	int s;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6; // ipv4 addrs 
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, port, &hints, &res);
	//assert(s==0);
	if (s)
	{
		fprintf(stderr, "failed to getaddrinfo-ipv6: %s\n", gai_strerror(s));
		return NULL;
	}
	return res;
}

int set_nonblock(int fd)
{
	int flags = -1;
	if(-1 == (flags = fcntl(fd, F_GETFL, 0)))
	{
		return -1;
	}
	flags |= O_NONBLOCK;
	if( fcntl(fd, F_SETFL, flags) == -1 )
	{
		return -1;
	}
	return 0;
}

int tcpipv4_createfd_bind(struct addrinfo* rp)
{
	int flags = -1;
	int s;
	// create socket 
	int sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	//assert(sfd!=-1);
	if (sfd == -1) 
	{
		fprintf(stderr, "failed to create socket\n");
		return -1;
	}
	// bind
	s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
	//assert(s==0);
	if(s!=0)
	{
		fprintf(stderr, "failed to bind socket %d\n", sfd);
		return -1;
	}
	// nonblock
	s = set_nonblock(sfd);
	//assert(s != -1);
	if (s == -1)
	{
		fprintf(stderr, "failed to set nonblocking socket %d\n", sfd);
		return -1;
	}
	return sfd;
}

int writen(int fd, char * buf, size_t len)
{
	char * cur = buf;
	int n = -1;
	while(len>0)
	{
		n = write(fd, cur, len);
		if (n<=0)
		{
			if(errno == EINTR) continue;
			else return -1;
		}
		len -= n;
		cur += n;
	}
	return 0;
}

int readn(int fd, char* buf, size_t len)
{
	char *cur = buf;
	int n = -1;
	while (len>0)
	{
		n = read(fd, cur, len);
		if (n == -1)
		{
			if (errno == EINTR)
				continue;
			else break;
		}
		else if (n == 0)
			break;
		cur += n; len -= n;
	}
	return (int)(cur-buf);
}

void accept_handler(int efd, int listenfd)
{
	struct epoll_event event;
	int s;
	while(1)
	{
		struct sockaddr in_addr;
		socklen_t in_addrlen = sizeof(struct sockaddr);
		int infd = -1;
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
				
		TRACE( infd = accept(listenfd, &in_addr, &in_addrlen) );
		//assert(infd != -1);
		if(infd == -1)
		{
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				;
			else
				perror("failed to accept\n");
			return;
		}
		s = getnameinfo(&in_addr, in_addrlen, 
				hbuf, sizeof(hbuf), 
				sbuf, sizeof(sbuf),
				NI_NUMERICHOST | NI_NUMERICSERV);
		//assert(s == 0);
		if(s == 0)
		{
			printf("Accept fd %d host %s port %s\n", infd, hbuf, sbuf);
			TRACE(s = set_nonblock(infd));
			//assert(s!=-1);
			event.data.fd = infd;
			event.events = EPOLLIN | EPOLLET;
			TRACE(s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event));
			//assert(s != -1);
			return;
		}
	}
	return;
}

void read_handler(int efd, int fd)
{
	//do sonething with buf.
	int s = -1;
	TRACE(s=readn(fd, buf, sizeof(buf)));
	buf[s] = 0;
	//printf("recv %d bytes: %s", s, buf);
	if(s < 0)
	{
		close(fd);
		if(-1 == epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL) )
			fprintf(stderr, "failed to del event of %d\n", fd);
		printf("close conection on fd %d", fd);
	}
	else if(s > 0)
	{
		//do sonething with buf.
		TRACE(user_recv_handler(efd, fd, buf, s));
	}
}


void write_handler(int efd, int fd)
{
	TRACE(writen(fd, buf, strlen(buf)));
	if(-1 == epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL) )
		fprintf(stderr, "failed to del event of %d\n", fd);
	close(fd);
}

int main(int argc, char ** argv)
{
	char* port = NULL;
	int listenfd = -1;
	struct addrinfo* hostaddr=NULL; 
	struct addrinfo* rp = NULL;
	struct epoll_event event;
	struct epoll_event * events, *cur_ev;
	int efd = -1;
	int num_ev = -1;
	int s;
	
	port = argv[1];
	// get server ipv4 address by getaddrinfo
	(rp = hostaddr = tcpipv4_getaddrinfo(port));
	// create and bind listening socket
	for(; rp; rp = rp->ai_next)
	{
		(listenfd = tcpipv4_createfd_bind(rp));
		if(-1 == listenfd)
			continue;
	}
	freeaddrinfo(hostaddr);	
	//assert(listenfd!=-1);
	if(listenfd==-1)
		exit(EXIT_FAILURE);
	//start listening 
	(s = listen(listenfd, SOMAXCONN));
	//assert(s!=-1);
	if(s == -1)
		exit(EXIT_FAILURE);
	// create epoll
	efd = epoll_create(MAXEVENTS);
	//assert(efd != -1);
	if(efd == -1)
		exit(EXIT_FAILURE);

	event.data.fd = listenfd;
	// epoll: read, ET
	event.events = EPOLLIN | EPOLLET;
	s = epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event);
	//assert(s!=-1);
	if(s==-1)
		exit(EXIT_FAILURE);

	events = (struct epoll_event*)calloc(MAXEVENTS, sizeof(struct epoll_event));

	// event loop;
	while (1)
	{
		num_ev = epoll_wait(efd, events, MAXEVENTS, -1);
		// for each active event: 
		while(num_ev--)
		{
			cur_ev = events+num_ev;
			// close the fd if error (ERR) or hang up (HUP)
			if(cur_ev->events & EPOLLERR || 
				cur_ev->events & EPOLLHUP)
			{
				fprintf(stderr, "epoll get event error\n");
				close(cur_ev->data.fd);
				continue;
			}
			// one or more new connections (fd = listenfd)
			else if(cur_ev->data.fd == listenfd)
			{
				accept_handler(efd, listenfd);
				continue;
			}
			else if(cur_ev->events & EPOLLIN)
			{
				// since the registered event is EPOLLIN, 
				// here we have data on fd waiting for reading.		
				TRACE(read_handler(efd, cur_ev->data.fd));
			}
			else if (cur_ev->events & EPOLLOUT)
			{
				TRACE(write_handler(efd, cur_ev->data.fd));
			}
		}
	}
	free(events); events = NULL;
	close(listenfd);
	exit(EXIT_SUCCESS);
}



