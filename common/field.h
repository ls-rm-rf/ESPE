// common/field.h
#pragma once
#include <stdint.h>

static const __uint128_t MODP = ((__uint128_t)2305843009213693951ULL);

static inline uint64_t mod_add(uint64_t a, uint64_t b){
    __uint128_t s = (__uint128_t)a + b;
    if (s >= MODP) s -= MODP;
    return (uint64_t)s;
}
static inline uint64_t mod_sub(uint64_t a, uint64_t b){
    return (a >= b) ? (a-b) : (uint64_t)(MODP - (((__uint128_t)b)-a));
}
static inline uint64_t mod_mul(uint64_t a, uint64_t b){
    __uint128_t z = (__uint128_t)a * b;
    // Barrett-like reduce, MODP is Mersenne 2^61-1 -> fast reduction
    uint64_t low = (uint64_t)z & ((1ULL<<61)-1);
    uint64_t high = (uint64_t)(z >> 61);
    uint64_t res = low + high;
    if (res >= MODP) res -= MODP;
    return res;
}
uint64_t mod_pow(uint64_t a, uint64_t e);
uint64_t mod_inv(uint64_t a);

