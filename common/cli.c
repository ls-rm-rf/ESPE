// common/cli.c
#include "cli.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int parse_args(int argc, char** argv, args_t* a, int for_km){
    memset(a,0,sizeof(*a));
    a->k=3; a->m=0;
    a->host="0.0.0.0"; a->port=1234;
    a->km_host="127.0.0.1"; a->km_port=9001;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-r") && i+1<argc) a->role=atoi(argv[++i]);
        else if(!strcmp(argv[i],"-N") && i+1<argc) a->N=atoi(argv[++i]);
        else if(!strcmp(argv[i],"-h") && i+1<argc) a->host=argv[++i];
        else if(!strcmp(argv[i],"-pn")&& i+1<argc) a->port=(uint16_t)atoi(argv[++i]);
        else if(!strcmp(argv[i],"-D") && i+1<argc) a->D=argv[++i];
        else if(!strcmp(argv[i],"-k") && i+1<argc) a->k=atoi(argv[++i]);
        else if(!strcmp(argv[i],"-m") && i+1<argc) a->m=atoi(argv[++i]);
        else if(!strcmp(argv[i],"-kh")&& i+1<argc) a->km_host=argv[++i];
        else if(!strcmp(argv[i],"-kpn")&& i+1<argc) a->km_port=(uint16_t)atoi(argv[++i]);
        else { fprintf(stderr,"Unknown or incomplete arg: %s\n", argv[i]); return -1; }
    }
    if(for_km) return 0;
    if(a->role!=1 && a->role!=2){ fprintf(stderr,"-r must be 1 (C) or 2 (D)\n"); return -1; }
    if(a->role==1 && a->N<=0){ fprintf(stderr,"-N must be >0 for role 1\n"); return -1; }
    if(!a->D){ fprintf(stderr,"-D required\n"); return -1; }
    return 0;
}

