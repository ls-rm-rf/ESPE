// common/field.c
#include "field.h"
uint64_t mod_pow(uint64_t a, uint64_t e){
    uint64_t r = 1;
    while(e){
        if(e&1) r = mod_mul(r,a);
        a = mod_mul(a,a);
        e >>= 1;
    }
    return r;
}
uint64_t mod_inv(uint64_t a){
    // Fermat: a^(p-2) mod p
    return mod_pow(a, (uint64_t)2305843009213693951ULL-2);
}

