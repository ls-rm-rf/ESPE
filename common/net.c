// common/net.c
#define _GNU_SOURCE
#include "net.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int set_reuse(int fd){
    int y=1; return setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&y,sizeof(y));
}

int tcp_listen(const char* host, uint16_t port, int backlog){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    if(fd<0) return -1;
    set_reuse(fd);
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(port);
    a.sin_addr.s_addr = host? inet_addr(host): htonl(INADDR_ANY);
    if(bind(fd,(struct sockaddr*)&a,sizeof(a))<0){ close(fd); return -1; }
    if(listen(fd,backlog)<0){ close(fd); return -1; }
    return fd;
}

int tcp_connect(const char* host, uint16_t port){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    if(fd<0) return -1;
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(port);
    a.sin_addr.s_addr = inet_addr(host);
    if(connect(fd,(struct sockaddr*)&a,sizeof(a))<0){ close(fd); return -1; }
    return fd;
}

int accept_nb(int lfd){
    return accept(lfd,NULL,NULL);
}

int send_all(conn_t* c, const void* buf, size_t len){
    const char* p = (const char*)buf; 
    size_t n=0;
    while(n<len){
        ssize_t w = send(c->fd, p+n, len-n, MSG_NOSIGNAL);
        if(w <= 0){ 
            if(errno == EINTR) continue; 
            fprintf(stderr, "send_all failed: errno=%d, sent=%zu, total=%zu\n", 
                   errno, n, len);
            return -1; 
        }
        n += w; 
        c->bytes_sent += w;
    }
    return 0;
}

int recv_all(conn_t* c, void* buf, size_t len){
    char* p = (char*)buf; 
    size_t n=0;
    while(n<len){
        ssize_t r = recv(c->fd, p+n, len-n, 0);
        if(r <= 0){ 
            if(errno == EINTR) continue; 
            fprintf(stderr, "recv_all failed: errno=%d, received=%zu, total=%zu\n", 
                   errno, n, len);
            return -1; 
        }
        n += r; 
        c->bytes_recv += r;
    }
    return 0;
}

int send_line(conn_t* c, const char* s){
    size_t len = strlen(s);
    if(send_all(c,s,len)) return -1;
    return 0;
}

int recv_line(conn_t* c, char* buf, size_t cap){
    size_t n=0;
    while(n+1<cap){
        char ch;
        ssize_t r = recv(c->fd, &ch, 1, 0);
        if(r<=0) return -1;
        c->bytes_recv += r;
        if(ch=='\n'){ buf[n]=0; return (int)n; }
        buf[n++]=ch;
    }
    return -1;
}
