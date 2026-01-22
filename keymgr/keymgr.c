#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h> 
#include "common/net.h"
#include "common/cli.h"
#include "ring/lsag.h"

// 简单行协议：客户端发 "GET\n"，返回一行 JSON: {"keys":[base64,...]}
static void b64(const uint8_t* in, size_t n, char* out, size_t outcap){
    sodium_bin2base64(out,outcap,in,n,sodium_base64_VARIANT_ORIGINAL);
}

int main(int argc, char** argv){
    if (sodium_init()<0) { fprintf(stderr,"sodium init fail\n"); return 1; }
    args_t a; if(parse_args(argc,argv,&a,1)) return 1;
    // 监听端口 a.port
    int lfd = tcp_listen(a.host, a.port? a.port:9001, 128);
    if(lfd<0){ perror("listen"); return 1; }
    // 初始化公钥池（3-5个）
    uint8_t pool[8][PUBKEY_LEN]; int pooln = 3 + (randombytes_uniform(3)); // 3~5
    for(int i=0;i<pooln;i++){
        ed25519_kp_t kp; ed25519_gen_kp(&kp);
        memcpy(pool[i], kp.pk, PUBKEY_LEN);
    }
    fprintf(stderr,"KeyMgr on %s:%u with %d keys\n", a.host, a.port? a.port:9001, pooln);
    while(1){
        int fd = accept_nb(lfd);
        if(fd<0) continue;
        conn_t c = {.fd=fd};
        char line[64]={0};
        if(recv_line(&c,line,sizeof(line))<=0){ close(fd); continue; }
        if(strcmp(line,"GET")==0){
            // 随机选 3-5
            int k = 3 + (randombytes_uniform(3)); if(k>pooln) k=pooln;
            int idx[5]; for(int i=0;i<k;i++){ idx[i]=randombytes_uniform(pooln); }
            // 打包 JSON
            char out[2048]; size_t off=0;
            off += snprintf(out+off,sizeof(out)-off,"{\"keys\":[");
            for(int i=0;i<k;i++){
                char b[64]; b64(pool[idx[i]],32,b,sizeof(b));
                off += snprintf(out+off,sizeof(out)-off,"\"%s\"%s", b, (i+1<k)?",":"");
            }
            off += snprintf(out+off,sizeof(out)-off,"]}\n");
            send_all(&c,out,off);
        }
        close(fd);
    }
    return 0;
}
