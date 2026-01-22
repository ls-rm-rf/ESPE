// common/util.c
#include "util.h"
#include "field.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void timer_start(stopwatch_t* t){ clock_gettime(CLOCK_MONOTONIC, &t->t0); }
void timer_stop(stopwatch_t* t){ clock_gettime(CLOCK_MONOTONIC, &t->t1); }
double timer_secs(const stopwatch_t* t){
    double s = (t->t1.tv_sec - t->t0.tv_sec)
             + (t->t1.tv_nsec - t->t0.tv_nsec) / 1e9;
    return s < 0 ? 0 : s;
}

uint64_t parse_u64(const char* s){
    char* e=0; errno=0;
    unsigned long long v = strtoull(s,&e,10);
    if(errno||*e) return 0; 
    return (uint64_t)v;  // 修复：将返回语句放在新的一行
}

int split_csv_int64(const char* s, uint64_t* out, int maxn){
    int n=0; const char* p=s;
    while(*p && n<maxn){
        char* end; unsigned long long v = strtoull(p,&end,10);
        out[n++]=(uint64_t)v;
        if(*end==',') p=end+1; else { p=end; break; }
    }
    return n;
}

uint64_t urand_nonzero_modp(){
    uint64_t x;
    do { randombytes_buf(&x,sizeof(x)); x &= ((1ULL<<61)-1); } while(x==0);
    return x;
}
