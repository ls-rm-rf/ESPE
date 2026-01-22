// ring/lsag.c - 彻底修复版本
#include "lsag.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

// 供外部使用的接口
void ed25519_gen_kp(ed25519_kp_t* kp) {
    if (crypto_sign_ed25519_keypair(kp->pk, kp->sk) != 0) {
        memset(kp, 0, sizeof(*kp));
    }
}

void lsag_sig_free(lsag_sig_t* sig) {
    if (!sig) return;
    if (sig->s) { 
        free(sig->s);
        sig->s = NULL; 
    }
    sig->n = 0;
}

// ---- 内部工具 ----
static void H_scalar(const uint8_t* data, size_t len, uint8_t out32[32]) {
    uint8_t h[64];
    crypto_hash_sha512(h, data, len);
    crypto_core_ed25519_scalar_reduce(out32, h);
}

static void Hp_point(const uint8_t* data, size_t len, uint8_t P[32]) {
    uint8_t u[32];
    crypto_generichash(u, sizeof u, data, len, NULL, 0);
    crypto_core_ed25519_from_uniform(P, u);
}

static int key_image(const uint8_t pk[32], const uint8_t sk[64], uint8_t I[32]) {
    uint8_t HpP[32];
    Hp_point(pk, 32, HpP);
    
    // 正确提取标量：对seed进行SHA-512，然后修剪
    uint8_t hash[64];
    crypto_hash_sha512(hash, sk, 32);  // sk的前32字节是seed
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    if (crypto_scalarmult_ed25519_noclamp(I, hash, HpP) != 0) {
        memset(I, 0, 32);
        return -1;
    }
    return 0;
}

static int validate_ring(const uint8_t ring[][32], uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        if (crypto_core_ed25519_is_valid_point(ring[i]) != 1) return -1;
    }
    return 0;
}

// ---- LSAG 签名/验签 ----
int lsag_sign(const uint8_t* m, size_t mlen,
              const uint8_t ring[][32], uint32_t n,
              const uint8_t sk[64], uint32_t idx,
              lsag_sig_t* sig)
{
    if (!m || !ring || !sig || !sk) return -1;
    if (n == 0 || idx >= n) return -1;
    if (validate_ring(ring, n) != 0) return -1;

    uint8_t P[32];
    crypto_sign_ed25519_sk_to_pk(P, sk);

    uint8_t I[32];
    if (key_image(P, sk, I) != 0) return -1;

    // 初始化签名结构
    memset(sig, 0, sizeof(*sig));
    sig->n = n;
    memcpy(sig->key_image, I, 32);
    
    // 分配 s 数组 - 使用 calloc 确保内存清零
    sig->s = (uint8_t*)calloc((size_t)n, 32);
    if (!sig->s) {
        return -1;
    }

    // 生成有效的随机标量 u
    uint8_t u[32]; 
    crypto_core_ed25519_scalar_random(u);
    
    uint8_t L[32];
    if (crypto_scalarmult_ed25519_base_noclamp(L, u) != 0) {
        lsag_sig_free(sig);
        return -1;
    }

    uint8_t HpP[32]; 
    Hp_point(P, 32, HpP);
    
    uint8_t R[32];
    if (crypto_scalarmult_ed25519_noclamp(R, u, HpP) != 0) {
        lsag_sig_free(sig);
        return -1;
    }

    // 计算初始挑战
    size_t buf_size = 64 + (mlen ? mlen : 1);
    uint8_t* buf = (uint8_t*)malloc(buf_size);
    if (!buf) {
        lsag_sig_free(sig);
        return -1;
    }
    
    memcpy(buf, L, 32);
    memcpy(buf + 32, R, 32);
    if (mlen) {
        memcpy(buf + 64, m, mlen);
    } else {
        buf[64] = 0;
    }
    
    // 初始挑战（从签名者位置开始）
    uint8_t c_next[32];
    H_scalar(buf, 64 + (mlen ? mlen : 1), c_next);
    free(buf);

    // 环签名计算：从 idx+1 开始循环，直到回到 idx
    // 我们需要生成所有 n-1 个其他成员的 s 值，并追踪 c0
    uint8_t c0_stored[32];
    int have_c0 = 0;
    
    for (uint32_t count = 0; count < n; count++) {
        uint32_t i = (idx + 1 + count) % n;
        
        // 保存进入索引0时的挑战值
        if (i == 0) {
            memcpy(c0_stored, c_next, 32);
            have_c0 = 1;
        }
        
        // 如果回到签名者位置，停止（这时c_next是c_idx）
        if (i == idx) {
            break;
        }
        
        // 生成随机标量 s_i
        uint8_t s_i[32]; 
        crypto_core_ed25519_scalar_random(s_i);
        memcpy(sig->s + i * 32, s_i, 32);

        // 计算 L_i = s_i * G + c_next * P_i
        uint8_t Li1[32], Li2[32], Li[32];
        if (crypto_scalarmult_ed25519_base_noclamp(Li1, s_i) != 0) {
            lsag_sig_free(sig);
            return -1;
        }
        if (crypto_scalarmult_ed25519_noclamp(Li2, c_next, ring[i]) != 0) {
            lsag_sig_free(sig);
            return -1;
        }
        crypto_core_ed25519_add(Li, Li1, Li2);

        // 计算 R_i = s_i * Hp(P_i) + c_next * I
        uint8_t HpPi[32]; 
        Hp_point(ring[i], 32, HpPi);
        
        uint8_t Ri1[32], Ri2[32], Ri[32];
        if (crypto_scalarmult_ed25519_noclamp(Ri1, s_i, HpPi) != 0) {
            lsag_sig_free(sig);
            return -1;
        }
        if (crypto_scalarmult_ed25519_noclamp(Ri2, c_next, I) != 0) {
            lsag_sig_free(sig);
            return -1;
        }
        crypto_core_ed25519_add(Ri, Ri1, Ri2);

        // 计算下一个挑战
        buf = (uint8_t*)malloc(buf_size);
        if (!buf) {
            lsag_sig_free(sig);
            return -1;
        }
        
        memcpy(buf, Li, 32);
        memcpy(buf + 32, Ri, 32);
        if (mlen) {
            memcpy(buf + 64, m, mlen);
        } else {
            buf[64] = 0;
        }
        
        H_scalar(buf, 64 + (mlen ? mlen : 1), c_next);
        free(buf);
    }
    
    // 如果idx == n-1，c0就是最初的挑战
    if (!have_c0) {
        // idx must be n-1, 重新计算初始挑战作为c0
        size_t b_size = 64 + (mlen ? mlen : 1);
        uint8_t* b = (uint8_t*)malloc(b_size);
        if (!b) {
            lsag_sig_free(sig);
            return -1;
        }
        memcpy(b, L, 32);
        memcpy(b + 32, R, 32);
        if (mlen) {
            memcpy(b + 64, m, mlen);
        } else {
            b[64] = 0;
        }
        H_scalar(b, b_size, c0_stored);
        free(b);
    }

    // 保存 c0 和计算 s_idx
    memcpy(sig->c0, c0_stored, 32);
    
    // c_next 现在是 c_idx，用于计算签名者的响应
    // c_next 现在是 c_idx，用于计算签名者的响应
    // 正确提取标量
    uint8_t hash[64];
    crypto_hash_sha512(hash, sk, 32);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    
    uint8_t cx[32];
    crypto_core_ed25519_scalar_mul(cx, c_next, hash);
    
    uint8_t sidx[32];
    crypto_core_ed25519_scalar_sub(sidx, u, cx);
    memcpy(sig->s + idx * 32, sidx, 32);
    
    return 0;
}

int lsag_verify(const uint8_t* m, size_t mlen,
                const uint8_t ring[][32], uint32_t n,
                const lsag_sig_t* sig)
{
    if (!m || !ring || !sig) return 0;
    if (n == 0 || sig->n != n || !sig->s) return 0;
    if (validate_ring(ring, n) != 0) return 0;

    uint8_t c[32]; 
    memcpy(c, sig->c0, 32);

    for (uint32_t i = 0; i < n; i++) {
        // 重新计算 L_i = s_i * G + c * P_i
        uint8_t L1[32], L2[32], L[32];
        if (crypto_scalarmult_ed25519_base_noclamp(L1, sig->s + i * 32) != 0) return 0;
        if (crypto_scalarmult_ed25519_noclamp(L2, c, ring[i]) != 0) return 0;
        crypto_core_ed25519_add(L, L1, L2);

        // 重新计算 R_i = s_i * Hp(P_i) + c * key_image
        uint8_t HpPi[32]; 
        Hp_point(ring[i], 32, HpPi);
        
        uint8_t R1[32], R2[32], R[32];
        if (crypto_scalarmult_ed25519_noclamp(R1, sig->s + i * 32, HpPi) != 0) return 0;
        if (crypto_scalarmult_ed25519_noclamp(R2, c, sig->key_image) != 0) return 0;
        crypto_core_ed25519_add(R, R1, R2);

        // 计算下一个挑战
        size_t buf_size = 64 + (mlen ? mlen : 1);
        uint8_t* buf = (uint8_t*)malloc(buf_size);
        if (!buf) return 0;
        
        memcpy(buf, L, 32);
        memcpy(buf + 32, R, 32);
        if (mlen) {
            memcpy(buf + 64, m, mlen);
        } else {
            buf[64] = 0;
        }
        
        uint8_t c_next[32];
        H_scalar(buf, 64 + (mlen ? mlen : 1), c_next);
        free(buf);
        
        memcpy(c, c_next, 32);
    }
    
    return sodium_memcmp(c, sig->c0, 32) == 0 ? 1 : 0;
}
