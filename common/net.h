// common/net.h
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    int fd;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
} conn_t;

int  tcp_listen(const char* host, uint16_t port, int backlog);
int  tcp_connect(const char* host, uint16_t port);
int  accept_nb(int lfd);

int  send_all(conn_t* c, const void* buf, size_t len);
int  recv_all(conn_t* c, void* buf, size_t len);
int  send_line(conn_t* c, const char* s);
int  recv_line(conn_t* c, char* buf, size_t cap);

