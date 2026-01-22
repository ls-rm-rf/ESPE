// test_basic.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "ring/lsag.h"

void test_basic_sign_verify() {
    printf("=== Testing Basic Sign/Verify ===\n");
    
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium init failed\n");
        return;
    }
    
    // 生成密钥对
    ed25519_kp_t kp;
    ed25519_gen_kp(&kp);
    printf("Generated keypair\n");
    
    // 创建环（3个成员）
    uint8_t ring[3][32];
    memcpy(ring[0], kp.pk, 32);
    
    ed25519_kp_t kp2, kp3;
    ed25519_gen_kp(&kp2);
    ed25519_gen_kp(&kp3);
    memcpy(ring[1], kp2.pk, 32);
    memcpy(ring[2], kp3.pk, 32);
    
    // 测试消息
    uint8_t msg[16] = "test message 123";
    
    // 签名
    lsag_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    
    printf("Signing message...\n");
    int sign_result = lsag_sign(msg, sizeof(msg), ring, 3, kp.sk, 0, &sig);
    printf("Sign result: %d, sig.n: %u\n", sign_result, sig.n);
    
    if (sign_result == 0 && sig.s != NULL) {
        printf("Signature successful, sig.s address: %p\n", (void*)sig.s);
        printf("First 16 bytes of sig.s: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", sig.s[i]);
        }
        printf("\n");
        
        // 验证
        printf("Verifying signature...\n");
        int verify_result = lsag_verify(msg, sizeof(msg), ring, 3, &sig);
        printf("Verify result: %d\n", verify_result);
        
        lsag_sig_free(&sig);
    } else {
        printf("Signature failed or sig.s is NULL\n");
        if (sig.s == NULL) {
            printf("sig.s is NULL!\n");
        }
    }
    
    printf("=== Test Complete ===\n");
}

int main() {
    test_basic_sign_verify();
    return 0;
}
