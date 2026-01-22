// common/poly.h
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct { size_t deg; uint64_t *coef; } poly_t;

poly_t poly_new(size_t deg);
void   poly_free(poly_t *p);
uint64_t poly_eval(const poly_t *p, uint64_t x);

// Lagrange interpolation from points (x[i], y[i]) -> poly degree <= n-1
poly_t lagrange_interpolate(const uint64_t *x, const uint64_t *y, size_t n);

// elementary symmetric polynomials e_t(values[0..n-1])
// returns array e[0..s] where e[0]=1, caller frees
uint64_t* elementary_symmetric(const uint64_t *vals, size_t n, size_t s);

