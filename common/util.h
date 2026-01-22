#pragma once
#include <stdint.h>
#include <time.h>

typedef struct { struct timespec t0, t1; } stopwatch_t;

void timer_start(stopwatch_t* t);
void timer_stop(stopwatch_t* t);
double timer_secs(const stopwatch_t* t);

uint64_t parse_u64(const char* s);
int split_csv_int64(const char* s, uint64_t* out, int maxn);
uint64_t urand_nonzero_modp();

