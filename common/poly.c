// common/poly.c
#include "poly.h"
#include "field.h"
#include <stdlib.h>
#include <string.h>
poly_t poly_new(size_t deg){
    poly_t p; p.deg=deg; p.coef = (uint64_t*)calloc(deg+1,sizeof(uint64_t)); return p;
}
void poly_free(poly_t *p){ if(p && p->coef){ free(p->coef); p->coef=NULL; p->deg=0; } }
uint64_t poly_eval(const poly_t *p, uint64_t x){
    uint64_t r=0;
    for (ssize_t i=(ssize_t)p->deg; i>=0; --i){
        r = mod_mul(r,x);
        r = mod_add(r, p->coef[i]);
    }
    return r;
}
poly_t lagrange_interpolate(const uint64_t *x, const uint64_t *y, size_t n){
    // O(n^2) implementation, degree <= n-1
    poly_t res = poly_new(n-1);
    for(size_t i=0;i<n;i++){
        // basis L_i(x)
        uint64_t denom=1;
        poly_t li = poly_new(1); li.coef[0]=1; li.coef[1]=0; // li(x)=1
        poly_free(&li); // We'll build via multiplying (x - xj)
        poly_t basis = poly_new(0); basis.coef[0]=1;
        for(size_t j=0;j<n;j++){
            if(i==j) continue;
            // multiply basis by (x - xj)
            poly_t nb = poly_new(basis.deg+1);
            for(size_t a=0;a<=basis.deg;a++){
                nb.coef[a] = mod_sub(nb.coef[a], mod_mul(basis.coef[a], x[j])); // *(-xj)
                nb.coef[a+1] = mod_add(nb.coef[a+1], basis.coef[a]);            // *x
            }
            poly_free(&basis); basis=nb;
            denom = mod_mul(denom, mod_sub(x[i], x[j]));
        }
        uint64_t inv = mod_inv(denom);
        uint64_t scale = mod_mul(y[i], inv);
        // res += basis * scale
        for(size_t a=0;a<=basis.deg;a++){
            res.coef[a] = mod_add(res.coef[a], mod_mul(basis.coef[a], scale));
        }
        poly_free(&basis);
    }
    // normalize degree
    while(res.deg>0 && res.coef[res.deg]==0) res.deg--;
    return res;
}
uint64_t* elementary_symmetric(const uint64_t *vals, size_t n, size_t s){
    uint64_t *e = (uint64_t*)calloc(s+1,sizeof(uint64_t));
    e[0]=1;
    for(size_t i=0;i<n;i++){
        // update from high to low
        size_t t = (i+1<s)?(i+1):s;
        for(size_t k=t;k>=1;k--){
            uint64_t tmp = mod_add(e[k], mod_mul(e[k-1], vals[i]));
            e[k]=tmp;
            if(k==1) break;
        }
    }
    return e;
}

