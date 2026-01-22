#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sodium.h>
#include "common/cli.h"
#include "common/net.h"
#include "common/util.h"
#include "common/field.h"
#include "common/poly.h"
#include "ring/lsag.h"

static void optimize_tcp(int fd) {
    int flag = 1;
    // 禁用Nagle算法
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    #ifdef TCP_QUICKACK
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
    #endif
    
    // 增大发送和接收缓冲区（关键修复）
    int bufsize = 256 * 1024;  // 256KB
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    
    // 设置TCP keepalive，防止长时间传输时断连
    int keepalive = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
}

static int fetch_ring_from_km(const char* host, uint16_t port,
                              uint8_t out[][32], int maxn) {
    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;
    
    conn_t c = {.fd = fd};
    if (send_line(&c, "GET\n")) {
        close(fd);
        return -1;
    }
    
    char buf[4096];
    int n = recv_line(&c, buf, sizeof(buf));
    close(fd);
    if (n <= 0) return -1;

    char *p = strchr(buf, '[');
    if (!p) return -1;
    p++;
    int cnt = 0;

    while (*p && cnt < maxn) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == ']') break;

        char *q = strchr(p, '\"');
        if (!q) break;
        q++;
        char *r = strchr(q, '\"');
        if (!r) return -1;
        
        size_t b64_len = (size_t)(r - q);
        if (b64_len == 0 || b64_len > 256) return -1;

        size_t bin_len = 0;
        if (sodium_base642bin(out[cnt], 32, q, b64_len, NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) != 0 || bin_len != 32) {
            p = r + 1;
            continue;
        }
        cnt++;
        p = r + 1;
    }

    return cnt > 0 ? cnt : -1;
}

static int send_com_and_points(conn_t* c, int m, int k, const uint64_t* rlist){
    char head[128]; 
    int len = snprintf(head,sizeof(head),"COM %d %d\n",m,k);
    if(send_all(c,head,len)) return -1;

    size_t buffer_size = (size_t)m * 24 + 2;
    char* line = (char*)malloc(buffer_size);
    if(!line) return -1;
    
    size_t off = 0;
    for(int i=0;i<m;i++){
        int written = snprintf(line+off, buffer_size-off, "%llu%s",
                (unsigned long long)rlist[i], (i+1<m)?" ":"\n");
        if (written < 0 || (size_t)written >= buffer_size-off) {
            free(line);
            return -1;
        }
        off += (size_t)written;
    }
    int rc = send_all(c,line,off);
    free(line);
    return rc;
}

static int recv_com_and_points(conn_t* c, int* out_m, int* out_k, uint64_t** out_r){
    char line[512];  // 增大缓冲区
    if(recv_line(c,line,sizeof(line))<=0) return -1;
    
    int m=0,k=0; 
    if(sscanf(line,"COM %d %d",&m,&k)!=2) return -1;
    if(recv_line(c,line,sizeof(line))<=0) return -1;
    if(m <= 0 || m > 1000) return -1;
    
    uint64_t* r = (uint64_t*)calloc((size_t)m,sizeof(uint64_t));
    if(!r) return -1;
    
    char* p=line;
    for(int i=0;i<m;i++){
        unsigned long long v=0; 
        int eat=0;
        if(sscanf(p,"%llu%n",&v,&eat)!=1){ 
            free(r); 
            return -1; 
        }
        r[i]=(uint64_t)v; 
        p+=eat; 
        while(*p==' ') p++;
    }
    *out_m=m; *out_k=k; *out_r=r; 
    return 0;
}

static uint64_t compute_Pc(const uint64_t* vals, int n, const uint64_t* c, int s){
    uint64_t* e = elementary_symmetric(vals,(size_t)n,(size_t)s);
    if(!e) return 0;
    uint64_t acc=0;
    for(int t=1;t<=s;t++) {
        acc = mod_add(acc, mod_mul(c[t-1], e[t]));
    }
    free(e); 
    return acc;
}

static uint32_t htonl_uint32(uint32_t hostlong) { return htonl(hostlong); }
static uint32_t ntohl_uint32(uint32_t netlong) { return ntohl(netlong); }

int main(int argc, char** argv){
    signal(SIGPIPE, SIG_IGN);

    if (sodium_init()<0) return 1;
    args_t a; 
    if(parse_args(argc,argv,&a,0)) return 1;

    if(a.role==1){
        // 计算方 C
        uint64_t coeff[32]; 
        int s = split_csv_int64(a.D, coeff, 32);
        if(s<=0) return 1;
        int k = a.k;
        int m = a.m>0? a.m : (s*k + 1);
        if(m <= 0) return 1;

        uint64_t* r = (uint64_t*)calloc((size_t)m,sizeof(uint64_t));
        if(!r) return 1;
        
        for(int i=0;i<m;i++){
            uint64_t x;
            int attempts = 0;
            do{
                if (attempts++ > 1000) {
                    free(r);
                    return 1;
                }
                x = urand_nonzero_modp();
                int clash=0; 
                for(int t=0;t<i;t++) {
                    if(r[t]==x){clash=1;break;}
                }
                if(!clash){ r[i]=x; break; }
            }while(1);
        }

        int lfd = tcp_listen(a.host, a.port, 128);
        if(lfd < 0){ 
            free(r); 
            return 1; 
        }

        conn_t* peers = (conn_t*)calloc((size_t)a.N,sizeof(conn_t));
        if(!peers){ 
            close(lfd); 
            free(r); 
            return 1; 
        }

        // 接受所有连接并优化
        fprintf(stderr, "Waiting for %d connections...\n", a.N);
        for(int i=0;i<a.N;i++){
            int fd = accept_nb(lfd);
            if(fd<0){ 
                for(int j=0;j<i;j++) close(peers[j].fd);
                close(lfd); 
                free(peers); 
                free(r); 
                return 1; 
            }
            optimize_tcp(fd);  // 立即优化TCP
            peers[i].fd=fd;
        }

        // 等待所有数据方就绪（单向同步）
        for(int i=0;i<a.N;i++){
            uint8_t ready;
            if(recv_all(&peers[i], &ready, 1) || ready != 'R'){
                for(int j=0;j<a.N;j++) close(peers[j].fd);
                close(lfd); 
                free(peers); 
                free(r); 
                return 1;
            }
        }

        stopwatch_t T; 
        timer_start(&T);

        // 发送COM到所有数据方
        for(int i=0;i<a.N;i++){
            if(send_com_and_points(&peers[i],m,k,r)){ 
                return 1;
            }
        }

        uint64_t* vals = (uint64_t*)calloc((size_t)m * (size_t)a.N, sizeof(uint64_t));
        if(!vals){ 
            for(int i=0;i<a.N;i++) close(peers[i].fd); 
            close(lfd); 
            free(peers); 
            free(r); 
            return 1; 
        }

        // 接收所有数据方的数据
        for(int i=0;i<a.N;i++){
            uint32_t cnt_net, cnt;
            if(recv_all(&peers[i], &cnt_net, 4)) return 1;
            cnt = ntohl_uint32(cnt_net);
            if(cnt != (uint32_t)m) return 1;

            for(int j=0;j<m;j++){
                uint64_t rj=0, vij=0;
                uint32_t siglen_net, siglen;
                uint8_t c0[32], key_image[32];
                uint32_t sig_n_net, sig_n;
                uint8_t ringcnt;

                if(recv_all(&peers[i], &rj, sizeof(rj))) return 1;
                if(recv_all(&peers[i], &vij, sizeof(vij))) return 1;
                if(recv_all(&peers[i], &siglen_net, 4)) return 1;

                siglen = ntohl_uint32(siglen_net);
                if (siglen == 0 || siglen > 8192) return 1;

                if (recv_all(&peers[i], c0, 32)) return 1;
                if (recv_all(&peers[i], key_image, 32)) return 1;
                if (recv_all(&peers[i], &sig_n_net, 4)) return 1;
                sig_n = ntohl_uint32(sig_n_net);
                if (sig_n == 0 || sig_n > 16) return 1;

                size_t s_buf_size = (size_t)sig_n * 32;
                uint8_t* s_buf = (uint8_t*)malloc(s_buf_size);
                if (!s_buf) return 1;
                
                if (recv_all(&peers[i], s_buf, s_buf_size)) {
                    free(s_buf);
                    return 1;
                }

                if(recv_all(&peers[i], &ringcnt, 1)){ 
                    free(s_buf);
                    return 1; 
                }
                if(ringcnt == 0 || ringcnt > 16){ 
                    free(s_buf);
                    return 1; 
                }

                uint8_t (*ring)[32] = malloc((size_t)ringcnt * 32);
                if(!ring){ 
                    free(s_buf); 
                    return 1; 
                }
                
                if(recv_all(&peers[i], ring, (size_t)ringcnt * 32)){ 
                    free(s_buf); 
                    free(ring); 
                    return 1; 
                }

                lsag_sig_t sig;
                memset(&sig, 0, sizeof(sig));
                memcpy(sig.c0, c0, 32);
                memcpy(sig.key_image, key_image, 32);
                sig.n = sig_n;
                sig.s = s_buf;

                uint8_t msg[16]; 
                memcpy(msg, &rj, 8); 
                memcpy(msg + 8, &vij, 8);
                int ok = lsag_verify(msg, sizeof(msg), (const uint8_t (*)[32])ring, ringcnt, &sig);

                lsag_sig_free(&sig);
                free(ring);

                if(!ok) return 1;

                vals[(size_t)j*(size_t)a.N + (size_t)i] = vij;
            }
        }

        uint64_t* qy = (uint64_t*)calloc((size_t)m,sizeof(uint64_t));
        if(!qy) return 1;
        
        for(int j=0;j<m;j++){
            qy[j] = compute_Pc(&vals[(size_t)j*(size_t)a.N], a.N, coeff, s);
        }
        
        poly_t Q = lagrange_interpolate(r,qy,(size_t)m);
        uint64_t result = poly_eval(&Q, 0);
        timer_stop(&T);

        uint64_t tx=0; 
        for(int i=0;i<a.N;i++) tx += peers[i].bytes_sent;
        
        printf("RESULT=%llu\n", (unsigned long long)result);
        printf("TX_KB=%.3f\n", tx / 1024.0);
        printf("TIME_SEC=%.6f\n", timer_secs(&T));

        for(int i=0;i<a.N;i++) close(peers[i].fd);
        close(lfd);
        free(peers); 
        free(vals); 
        free(qy); 
        poly_free(&Q); 
        free(r);
        return 0;

    }else{
        // 数据方 D
        ed25519_kp_t kp; 
        ed25519_gen_kp(&kp);

        uint8_t ring[8][32];
        int rn = fetch_ring_from_km(a.km_host,a.km_port,ring,8);
        if(rn<=0) return 1;
        
        int dup=0; 
        for(int i=0;i<rn;i++) {
            if(memcmp(ring[i],kp.pk,32)==0){ 
                dup=1;
                break; 
            }
        }
        if(!dup){
            if(rn >= 8) return 1;
            memcpy(ring[rn], kp.pk, 32);
            rn++;
        }

        int fd = tcp_connect(a.host,a.port);
        if(fd<0) return 1;
        
        optimize_tcp(fd);  // 优化TCP
        conn_t c={.fd=fd};

        // 发送就绪信号
        uint8_t ready = 'R';
        if(send_all(&c, &ready, 1)) {
            close(fd);
            return 1;
        }

        int m=0,k=0; 
        uint64_t* r=NULL;
        if(recv_com_and_points(&c,&m,&k,&r)){ 
            close(fd); 
            return 1; 
        }

        stopwatch_t T; 
        timer_start(&T);

        uint64_t alpha = parse_u64(a.D);
        uint64_t *coef = (uint64_t*)calloc((size_t)k+1,sizeof(uint64_t));
        if(!coef){ 
            free(r); 
            close(fd); 
            return 1; 
        }
        
        coef[0]=alpha;
        for(int d=1; d<=k; d++) coef[d]=urand_nonzero_modp();
        poly_t Pi = {.deg=(size_t)k, .coef=coef};

        uint32_t cnt = (uint32_t)m;
        uint32_t cnt_net = htonl_uint32(cnt);
        if(send_all(&c, &cnt_net, sizeof(cnt_net))){ 
            free(r); 
            free(coef); 
            close(fd); 
            return 1; 
        }
        
        uint64_t tx_bytes = sizeof(cnt_net);

        for(int j=0;j<m;j++){
            uint64_t rj=r[j];
            uint64_t vij=poly_eval(&Pi,rj);

            uint8_t msg[16]; 
            memcpy(msg,&rj,8); 
            memcpy(msg+8,&vij,8);
            lsag_sig_t sig; 
            memset(&sig,0,sizeof(sig));

            int idx=-1;
            for(int i=0;i<rn;i++) {
                if(memcmp(ring[i],kp.pk,32)==0) {
                    idx=i; 
                    break;
                }
            }
            if(idx<0){ 
                free(r); 
                free(coef); 
                close(fd); 
                return 1; 
            }

            if(lsag_sign(msg,sizeof(msg),(const uint8_t (*)[32])ring,(uint32_t)rn,kp.sk,(uint32_t)idx,&sig)){
                free(r); 
                free(coef); 
                close(fd); 
                return 1;
            }

            uint32_t siglen = (uint32_t)(32 + 32 + 4 + sig.n * 32);
            uint32_t siglen_net = htonl_uint32(siglen);

            if (send_all(&c, &rj, sizeof(rj))) { 
                lsag_sig_free(&sig); 
                return 1; 
            }
            if (send_all(&c, &vij, sizeof(vij))) { 
                lsag_sig_free(&sig); 
                return 1; 
            }
            if (send_all(&c, &siglen_net, 4)) { 
                lsag_sig_free(&sig); 
                return 1; 
            }
            if (send_all(&c, sig.c0, 32)) {
                lsag_sig_free(&sig);
                return 1;
            }
            if (send_all(&c, sig.key_image, 32)) {
                lsag_sig_free(&sig);
                return 1;
            }

            uint32_t sig_n_net = htonl_uint32(sig.n);
            if (send_all(&c, &sig_n_net, 4)) {
                lsag_sig_free(&sig);
                return 1;
            }
            
            size_t s_buf_size = (size_t)sig.n * 32;
            if (sig.s == NULL) {
                lsag_sig_free(&sig);
                return 1;
            }
            
            if (send_all(&c, sig.s, s_buf_size)) {
                lsag_sig_free(&sig);
                return 1;
            }

            uint8_t ringcnt = (uint8_t)rn;
            if (send_all(&c, &ringcnt, 1)) { 
                lsag_sig_free(&sig); 
                return 1; 
            }
            
            size_t ring_size = (size_t)rn * 32;
            if (send_all(&c, ring, ring_size)) { 
                lsag_sig_free(&sig); 
                return 1; 
            }

            tx_bytes += sizeof(rj) + sizeof(vij) + 4 + siglen + 1 + ring_size;
            lsag_sig_free(&sig);
        }

        timer_stop(&T);
        
        printf("TX_KB=%.3f\n", tx_bytes / 1024.0);
        printf("TIME_SEC=%.6f\n", timer_secs(&T));

        free(r); 
        free(coef); 
        close(c.fd);
        return 0;
    }
}
