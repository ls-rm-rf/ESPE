// common/cli.h
#pragma once
#include <stdint.h>
typedef struct {
    int role;              // 1=C, 2=D
    int N;                 // number of data parties (C only)
    const char* host;      // peer host
    uint16_t port;         // peer port
    const char* D;         // C: coefficients csv; D: alpha
    int k;                 // max degree of Pi
    int m;                 // number of points (if 0 -> auto = s*k+1)
    const char* km_host;   // key manager host
    uint16_t km_port;      // key manager port
} args_t;

int parse_args(int argc, char** argv, args_t* a, int for_km);

