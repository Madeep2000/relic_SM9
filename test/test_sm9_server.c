/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */
#include "sm9.h"
#include <time.h>
#include "debug.h"
#include <pthread.h>
#include <omp.h>

#include "relic_test.h"
#include "relic_bench.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "gmssl/error.h"
#include <malloc.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

#include <stdint.h>
#include <getopt.h>

void print_usage(char *program_name) {
    printf("Usage: %s [--sign(=dir0)] [--enc(=dir0)] [--user-id=value] [--master-key-dir=dir1] [--user-key-dir=dir2] [-h]\n", program_name);
    printf("Options:\n");
	printf("--sign(=dir0)            Specify the path of sign master-private-key,generate such a key if there is no dir0.\n");
    printf("--enc(=dir0)             Specify the path of enc  master private key,generate such a key if there is no dir0.\n");
    printf("**NOTICE**: --sign --enc are opposing options\n");
    printf("--user-id=value          Specify user's id as user's public key\n");
    printf("--master-key-dir=dir1    Store a new master-private-key in dir1\n");
    printf("--user-key-dir=dir2      Store a new   user-private-key in dir2\n");
    printf("-h                       Print this help message and exit\n");
	printf("EXAMPLE1: %s --sign --master-key-dir=master_key_sign.bin\n",program_name);
    printf("EXAMPLE2: %s --enc=master_key_enc.bin --user-id=Alice --user-key-dir=userkey.bin\n",program_name);
}

/*
int main(){
    if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (pc_param_set_any() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
    SM9_SIGN_MASTER_KEY sign_master;
    SM9_ENC_MASTER_KEY enc_master;

    sign_master_key_init(&sign_master);
    enc_master_key_init(&enc_master);


    sign_master_key_free(&sign_master);
    enc_master_key_free(&enc_master);
    return 0;
}
*/

#define MAX_FILE_SIZE 1024

void read_file1(char *filename, char *buffer) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(1);
    }

    size_t bytes_read = fread(buffer, 1, MAX_FILE_SIZE - 1, fp);
    buffer[bytes_read] = '\0';

    fclose(fp);
}

int main(int argc, char *argv[]) {
    if(argc == 1){
       print_usage(argv[0]);
       return 1;
    }
    
    if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (pc_param_set_any() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
    SM9_SIGN_MASTER_KEY sign_master;
    SM9_ENC_MASTER_KEY enc_master;
    SM9_SIGN_KEY sign_user;
    SM9_ENC_KEY enc_user;

    //default ks and ke
    sign_master_key_init(&sign_master);
    enc_master_key_init(&enc_master);

    //just allocate memory
    sign_user_key_init(&sign_user);
    enc_user_key_init(&enc_user);

    uint8_t *msk_data = NULL;
    size_t msk_datalen = 0;

    uint8_t *usk_data[65];
    size_t usk_datalen = 64;

    uint8_t msk[32];

    int opt;

    int s_flag = 0;
    int e_flag = 0;
    int msk_flag = 0;
    int usk_flag = 0;

    int result = 0;
    char *ifile = NULL;
    char *ofile = NULL;
    char *usrsk = NULL;
    char *id = NULL;
    int idlen = 0;

    struct option long_options[] = {
        {"sign", optional_argument, NULL, 's'},
        {"enc", optional_argument, NULL, 'e'},
        {"user-id",required_argument, NULL, 'i'},
        {"master-key-dir",required_argument,NULL,'-'},
        {"user-key-dir",required_argument,NULL,'+'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc,argv,"s:e:i:+:-:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                if(optarg){
                    s_flag = 1;
                    //import ks from file
                    ifile = (char *)malloc(strlen(optarg) * sizeof(char));
				    strcpy((char *)ifile, optarg);
                    if (ifile == NULL) {
                        printf("Error: failed to allocate memory for inputfile.\n");
                        return 1;
                    }
                    result = read_file(ifile,&msk_data,&msk_datalen);
				    if(result == 0){
					    printf("FILE READING ERROR\n");
					    exit(1);
                    }
				}
                else{
                    //rand a ks
                    s_flag = 2;
                }
                break;
            case 'e':
                if(optarg){
                    //import ke from file
                    e_flag = 1;
                    ifile = (char *)malloc(strlen(optarg) * sizeof(char));
				    strcpy((char *)ifile, optarg);
                    if (ifile == NULL) {
                        printf("Error: failed to allocate memory for inputfile.\n");
                        return 1;
                    }
                    result = read_file(ifile,&msk_data,&msk_datalen);
				    if(result == 0){
					    printf("FILE READING ERROR\n");
					    exit(1);
                    }
                }
                else{
                    //rand a ke
                    e_flag = 2;
                }
                break;
            case 'i':
                idlen = strlen(optarg);
                id = (char *)malloc(idlen * sizeof(char));
				strcpy((char *)id, optarg);
                if (id == NULL) {
                    printf("Error: failed to allocate memory for id.\n");
                    return 1;
                }
                break;
            case '-':
                msk_flag = 1;
                ofile = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)ofile, optarg);
                if (ofile == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                break;
            case '+':
                usk_flag = 1;
                usrsk = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)usrsk, optarg);
                if (usrsk == NULL) {
                    printf("Error: failed to allocate memory for user-key.\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if(e_flag != 0 && s_flag != 0 ){
        fprintf(stderr, "Error: --sign --enc are mutually exclusive options.\n");
        exit(1);
    }


    if(s_flag != 0){
        if(s_flag == 1){
            sign_master_key_set(&sign_master,msk_data,msk_datalen);
        }
        else{
            sign_master_key_gen(&sign_master);
            msk_datalen = bn_size_bin(sign_master.ks);
            msk_data = (uint8_t *)malloc(msk_datalen * sizeof(uint8_t));
            bn_write_bin(msk_data, msk_datalen, sign_master.ks);
            //bn_write_str(msk,bn_size_str(sign_master.ks,16),sign_master.ks,16);
        }
        
        if(id != NULL){
            sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_user);
            //usk_datalen = 64;
            ep_print(sign_user.ds);
            ep_write_bin(usk_data,usk_datalen+1,sign_user.ds,0);
        }
    }
    else if(e_flag!=0){
        if(e_flag == 1){
            enc_master_key_set(&enc_master,msk_data);
        }
        else{
            enc_master_key_gen(&enc_master);
            msk_datalen = bn_size_bin(enc_master.ke);
            msk_data = (uint8_t *)malloc(msk_datalen * sizeof(uint8_t));
            bn_write_bin(msk_data,msk_datalen,enc_master.ke);
        }
    }

    bn_print(sign_master.ks);
    
    if(msk_flag == 1 ){
        write_file(ofile,msk_data,msk_datalen);
        if(s_flag == 1 || e_flag == 1){
            printf("NOTICE: The Contents in %s and %s are the same.\n",ifile,ofile);
        }
    }

    if(usk_flag == 1){
        write_file(usrsk,usk_data,usk_datalen);
    }

    sign_master_key_free(&sign_master);
    enc_master_key_free(&enc_master);
    sign_user_key_free(&sign_user);
    enc_user_key_free(&enc_user);
    free(msk_data);
    free(id);
    free(ifile);
    free(ofile);
    free(usrsk);
    return 0;
}