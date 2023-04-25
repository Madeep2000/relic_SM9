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
    printf("Relic-SM9 for server.\n");
    printf("Mods:\n");
    printf(" --setup | --keygen \n");
    printf("Details:\n\n");
    
    printf("--setup:                   Setup one pair of master public key and private key\n");
    printf("--alg=value                Specify the algorathm in value ( sign | enc )\n");
    printf("[--outfile=dir1]           Store the new master public key at dir1\n");
    printf("--outkey=dir2              Store the new master private key at dir2\n\n");

    printf("--keygen:                  Generate user's private key using user's id\n");
    printf("--alg=value1               Specify the algorathm in value ( sign | enc )");
    printf("--user-id=value2           Specify user's id as user's public key\n");
    printf("[--infile=dir1]            Specify master public key at dir1\n");
    printf("--inkey=dir2               Specify master private key at dir2\n");
    printf("--outkey=dir3              Store user's private key in dir3\n\n");
	printf("EXAMPLE1: %s --setup --alg=sign --outfile=masterpub.bin --outkey=masterkey.bin\n",program_name);
    printf("EXAMPLE2: %s --keygen --alg=enc --user-id=Alice --inkey=masterkey.bin --outkey=alicekey.abc\n\n",program_name);
    printf("-h                         Print this help message and exit\n");
}

/*
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
*/

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

    //sign_master_key_init(&sign_master);
    sign_master_key_gen(sign_master);
    //enc_master_key_init(&enc_master);
    enc_master_key_gen(&enc_master);

    //just allocate memory
    sign_user_key_init(&sign_user);
    enc_user_key_init(&enc_user);

    bn_t N;
    bn_null(N);
    bn_new(N);
    bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);

    struct option long_options[] = {
        {"setup", no_argument, NULL, 'u'},
        {"keygen", no_argument, NULL, 'g'},
        {"alg",required_argument, NULL, 'a'},
        {"user-id",required_argument, NULL, 'i'},
        {"infile",optional_argument,NULL,'+'},
        {"inkey",required_argument,NULL,'?'},
        {"outfile",optional_argument,NULL,'-'},
        {"outkey",required_argument,NULL,'='},
        {"help",no_argument,NULL,'h'},
        {0, 0, 0, 0}
    };
    int opt;
    int result = 0;
    int up_flag = 0;
    int gen_flag = 0;
    int s_flag = 0;
    int e_flag = 0; 

    char *ifile = NULL;
    char *in_key = NULL;
    char *ofile = NULL;
    char *out_key = NULL;
    char *id = NULL;
    
    uint8_t *msk_data = NULL;
    uint8_t *mpub_data = NULL;
    uint8_t *user_data = NULL;
    
    size_t msk_datalen = 0;
    size_t mpub_datalen = 0;
    size_t user_datalen = 0;

    uint8_t *data = NULL;
    uint8_t *key_data = NULL;

    int idlen = 0;
    int datalen = 0;
    int keylen = 0;

    while ((opt = getopt_long(argc,argv,"a:i:+:?:-:=:ugh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u':
                up_flag = 1;
                break;

            case 'g':
                gen_flag = 1;
                break;

            case 'a':
                if( strcmp(optarg,"sign") == 0 ){
                    s_flag = 1;
                }
                else if( strcmp(optarg,"enc") == 0 ){
                    e_flag = 1;
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

            case '+':
                ifile = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)ifile, optarg);
                if (ifile == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                result = read_file(ifile,&data,&datalen);
				if(result == 0){
					printf("FILE READING ERROR\n");
					exit(1);
				}
                break;
            case '?':
                in_key = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)in_key, optarg);
                if (in_key == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                result = read_file(in_key,&key_data,&keylen);
				if(result == 0){
					printf("FILE READING ERROR\n");
					exit(1);
				}
                break;

            case '-':
                ofile = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)ofile, optarg);
                if (ofile == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                break;
            case '=':
                out_key = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)out_key, optarg);
                if (out_key == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                break;
        }
    }
    if( up_flag + gen_flag != 1 ){
        fprintf(stderr, "Error: You must and can only choose one of these parameters : --setup | --keygen .\n");
        exit(1);
    }
    if( s_flag + e_flag != 1 ){
        fprintf(stderr, "Error: You must and can only choose one of these parameters : --alg=sign | --alg=enc .\n");
        exit(1);
    }

    if(up_flag == 1){
        if(s_flag == 1){
            msk_datalen = bn_size_bin(sign_master.ks);
            msk_data = (uint8_t *)malloc(msk_datalen * sizeof(uint8_t));
            bn_write_bin(msk_data, msk_datalen, sign_master.ks);

            write_file(out_key,msk_data,msk_datalen);

            if(ofile != NULL){
                mpub_datalen = ep2_size_bin(sign_master.Ppubs,0);
                mpub_data = (uint8_t *)malloc(mpub_datalen * sizeof(uint8_t));
                ep2_write_bin(mpub_data,mpub_datalen,sign_master.Ppubs,0);
                write_file(ofile,mpub_data,mpub_datalen);
            }
        }
        else{
            msk_datalen = bn_size_bin(enc_master.ke);
            msk_data = (uint8_t *)malloc(msk_datalen * sizeof(uint8_t));
            bn_write_bin(msk_data,msk_datalen,enc_master.ke);

            write_file(out_key,msk_data,msk_datalen);

            if(ofile != NULL){
                mpub_datalen = ep_size_bin(enc_master.Ppube,0);
                mpub_data = (uint8_t *)malloc(mpub_datalen * sizeof(uint8_t));
                ep_write_bin(mpub_data,mpub_datalen,enc_master.Ppube,0);
                write_file(ofile,mpub_data,mpub_datalen);
            }
        }
    }
    else if(gen_flag == 1){
        if( s_flag == 1 ){
            sign_master_key_set(&sign_master,key_data,keylen);
            sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_user);
            user_datalen = ep2_size_bin(sign_user.Ppubs,0);
            user_data = (uint8_t *)malloc(user_datalen * sizeof(uint8_t));
            ep2_write_bin(sign_user.Ppubs,user_data,user_datalen,0);

            write_file(out_key,user_data,user_datalen);

        }
        else{
            enc_master_key_set(&enc_master,key_data,keylen);
            sm9_enc_master_key_extract_key(&enc_master, (char *)id, idlen, &enc_user);
            user_datalen = ep_size_bin(enc_user.Ppube,0);
            user_data = (uint8_t *)malloc(user_datalen * sizeof(uint8_t));
            ep_write_bin(enc_user.Ppube,user_data,user_datalen,0);

            write_file(out_key,user_data,user_datalen);
        }
    }


    sign_master_key_free(&sign_master);
    enc_master_key_free(&enc_master);
    sign_user_key_free(&sign_user);
    enc_user_key_free(&enc_user);
    free(msk_data);
    free(mpub_data);
    free(user_data);
    free(data);
    free(key_data);
    free(id);
    free(ifile);
    free(in_key);
    free(ofile);
    free(out_key);
    
    return 0;
}