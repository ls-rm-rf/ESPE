// ring/lsag.h
#pragma once
#include <stddef.h>
#include <stdint.h>

#define PUBKEY_LEN 32
#define SECKEY_LEN 64

typedef struct { uint8_t pk[PUBKEY_LEN]; uint8_t sk[SECKEY_LEN]; } ed25519_kp_t;

void  ed25519_gen_kp(ed25519_kp_t* kp); // random
// --- LSAG ---
typedef struct {
    uint32_t n;           // ring size
    uint8_t c0[32];       // challenge
    uint8_t *s;           // s_i per ring member, n*32 bytes
    uint8_t key_image[32];
} lsag_sig_t;

int  lsag_sign(const uint8_t* msg, size_t mlen,
               const uint8_t ring[][PUBKEY_LEN], uint32_t n,
               const uint8_t seckey[SECKEY_LEN], uint32_t idx,
               lsag_sig_t* sig_out);

int  lsag_verify(const uint8_t* msg, size_t mlen,
                 const uint8_t ring[][PUBKEY_LEN], uint32_t n,
                 const lsag_sig_t* sig);

void lsag_sig_free(lsag_sig_t* s);
