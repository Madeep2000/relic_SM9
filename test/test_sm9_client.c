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
    printf("Relic-SM9 for client.\n");
    //printf("Usage: %s [sign|verify|kem|kdm|enc|dec] [--message=dir0] [--cipher=dir1] [--sign=dir2] [--verify=dir2'] [--kem=dir3] [--kdm=dir3'] [--enc=dir4] [--dec=dir4'] [--user-id=value] [--user-key-dir=dir5] [-h]\n", program_name);
    printf("Mods:\n");
    printf("[--sign|--verify|--kem|--kdm|--enc|--dec|--exchange]\n");
    printf("Details:\n");

    printf("\n--sign:                  Specify the signature operation.\n");
    printf("--inpub=dir1             Specify master's public key in dir1\n");
    printf("--inkey=dir2             Specify user's private key file in dir2.\n");
    printf("--infile=dir3            Specify the input file as plaintext/message in dir3.\n");
    printf("--outfile=dir4           Specify the output file as signature in dir4.\n");

    printf("\n--verify:                Specify the verification operation.\n");
    printf("--user-id=value          Specify user's id as user's public key\n");
    printf("--master-pub=dir1        Specify master's public key in dir1\n");
    printf("--infile=dir2            Specify the input file as plaintext/message in dir2.\n");
    printf("--insig=dir3             Specify the input file as signature in dir3.\n");
    printf("If the verification is successful, print Verified OK, otherwise print Verification Failure.\n");

    printf("\n--kem                    Specify the Key Encapsulation operation.\n");
    printf("--user-id=value          Specify user's id as user's public key\n");
    printf("--master-pub=dir1        Specify master's public key in dir1\n");
    printf("--outkey=dir2            Specify the output file as key in dir2.\n");
    printf("--outfile=dir3           Specify the output file as ciphertext in dir3.\n");


    printf("\n--kdm                    Specify the Key Decapsulation operation.\n");
    printf("--user-id=value          Specify user's id as user's public key\n");
    printf("--inkey=dir1             Specify user's private key file in dir1.\n");
    printf("--infile=dir2            Specify the input file as ciphertext in dir2.\n");
    printf("--inKEY=dir3             Specify the input file as secret key in dir3.\n");
    printf("--outkey=dir4            Specify the output file as key in dir4.\n");

    printf("\n--enc                    Specify the encryption operation.\n");
    printf("--user-id=value          Specify user's id as user's public key\n");
    printf("--master-pub=dir1        Specify master's public key in dir1\n");
    printf("--infile=dir2            Specify the input file as plaintext/message in dir2.\n");
    printf("--outfile=dir3           Specify the output file as ciphertext in dir3.\n");
    
    printf("\n--dec                    Specify the decryption operation.\n");
    printf("--user-id=value          Specify user's id as user's public key\n");
    printf("--inkey=dir1             Specify user's private key file in dir1.\n");
    printf("--infile=dir2            Specify the input file as ciphertext in dir2.\n");
    printf("--outfile=dir3           Specify the output file as plaintext in dir3.\n");

    printf("\n--exchange=role          Specify the key exchange operation and enter your role = [initiator | responder].\n");
    printf("--user-id=value1         Specify user's id as user's public key\n");
    printf("--other-id=value2        Specify another user's id as his/her public key\n");
    printf("--master-pub=dir1        Specify master's public key in dir1\n");
    printf("--inkey=dir2             Specify user's private key file in dir2.\n");
    printf("--inKEY=dir3             Specify the input file as another user's temporary public key in dir3.\n");
    printf("--outkey=dir4            Specify the output file as session key in dir4.");
    printf("--outKEY=dir5            Specify the output file as user's temporary public key in dir5.\n");
    printf("--check                  Check whether the key exchange is sussess.\n");
    printf("--infile=dir6            Specify the input file as another's hash option in dir6\n");
    printf("--outfile=dir7           Specify the output file as user's hash option in dir7.\n");

	printf("\nEXAMPLE1: %s --sign --inpub=pub.bin --inkey=Alicekey.bin --infile=message.bin --outfile=sig.bin\n",program_name);
    printf("EXAMPLE2: %s --verify --user-id=Alice --master-pub=pub.bin --infile=message.bin --insig=sig.bin\n",program_name);
    printf("EXAMPLE3: %s --kem --user-id=Bob --master-pub=pub.bin --outkey=key.bin --outfile=sig.bin\n",program_name);
    printf("EXAMPLE4: %s --kdm --user-id=Bob --inkey=key.bin --infile=cipher.bin --outkey=key.bin\n",program_name);
    printf("EXAMPLE5: %s --enc --user-id=Bob --master-pub=pub.bin --infile=message.bin --outfile=cipher.bin\n",program_name);
    printf("EXAMPLE6: %s --dec --user-id=Bob --inkey=key.bin --infile=cipher.bin --outfile=message.bin\n",program_name);
    

    printf("\n-h                     Print this help message and exit\n\n");
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
    SM9_SIGN_CTX ctx;

    //allocate memory
    sign_user_key_init(&sign_user);
    enc_user_key_init(&enc_user);

    sign_master_key_init(&sign_master);
    enc_master_key_init(&enc_master);

    int opt;
    int result = 0;

    //sign
    int s_flag = 0;
    //verify    
    int v_flag = 0;
    //kem
    int k_flag = 0;
    //kdm
    int m_flag = 0;
    //enc
    int e_flag = 0;
    //dec
    int d_flag = 0;
    //exchange
    int x_flag = 0;
    int check_flag = 0;

    char *ifile = NULL;
    char *ofile = NULL;
    char *user_id = NULL;
    char *other_id = NULL;
    char *in_pub = NULL;
    char *in_sig = NULL;
    char *in_key = NULL;
    char *in_K = NULL;
    char *out_key = NULL;
    char *out_K = NULL;
    
    uint8_t *data = NULL;
    uint8_t *pub_data = NULL;
    uint8_t *key_data = NULL;
    uint8_t *K_data = NULL;
    uint8_t *sig_data = NULL;

    uint8_t out[1000];
	size_t outlen = 0;

    uint8_t kbuf[287];
    size_t klen = 32;

    uint8_t sa[32];
    int salen = 32;
    int publen = 0;
    int siglen = 0;
    int keylen = 0;
    int Klen = 0;
    int idlen = 0;
    int other_idlen = 0;
    int datalen = 0;
    int init = 0;
    int resp = 0;

    struct option long_options[] = {
        {"sign", no_argument, NULL, 's'},
        {"verify", no_argument, NULL, 'v'},
        {"kem",no_argument, NULL, 'k'},
        {"kdm",no_argument, NULL, 'm'},
        {"enc",no_argument, NULL, 'e'},
        {"dec",no_argument, NULL, 'd'},
        {"check",no_argument, NULL, '@'},
        {"exchange",required_argument, NULL, 'x'},
        {"user-id",required_argument, NULL, 'i'},
        {"other-id",required_argument, NULL, 'r'},
        {"inkey",required_argument,NULL,'?'},
        {"inKEY",required_argument,NULL,'K'},
        {"master-pub",required_argument,NULL,'!'},
        {"insig",required_argument,NULL,'g'},
        {"infile",required_argument,NULL,'+'},
        {"outfile",required_argument,NULL,'-'},
        {"outkey",required_argument,NULL,'='},
        {"outKEY",required_argument,NULL,'o'},
        {"help",no_argument,NULL, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc,argv,"K:?:!:g:i:+:-:r:=:o:@svkmedxh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'x':
                x_flag = 1;
                if( (optarg == 1) || (strcmp(optarg,"initiator") == 0) ){
                    init = 1;
                }
                else if( (optarg == -1) || (strcmp(optarg,"responder") == 0) ){
                    resp = 1;
                }
                else{
                    printf("EROOR:invalid parameter\n");
                    return -1;
                }
                break;
            case '@':
                check_flag = 1;
                break;
            case 's':
                s_flag = 1;
                break;
            case 'v':
                v_flag = 1;
                break;
            case 'k':
                k_flag = 1;
                break;
            case 'm':
                m_flag = 1;
                break;
            case 'e':
                e_flag = 1;
                break;
            case 'd':
                d_flag = 1;
                break;
            case 'i':
                idlen = strlen(optarg);
                user_id = (char *)malloc(idlen * sizeof(char));
				strcpy((char *)user_id, optarg);
                if (user_id == NULL) {
                    printf("Error: failed to allocate memory for id.\n");
                    return 1;
                }
                break;
            case 'r':
                other_idlen = strlen(optarg);
                other_id = (char *)malloc(other_idlen * sizeof(char));
				strcpy((char *)other_id, optarg);
                if (other_id == NULL) {
                    printf("Error: failed to allocate memory for id.\n");
                    return 1;
                }
                break;
            case 'K':
                in_K = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)in_K, optarg);
                if (in_K == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                result = read_file(&K_data,&Klen,in_K);
				if(result == 0){
					printf("KEY FILE READING ERROR\n");
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
                result = read_file(&key_data,&keylen,in_key);
				if(result == 0){
					printf("KEY FILE READING ERROR\n");
					exit(1);
				}
                break;
            case '!':
                in_pub = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)in_pub, optarg);
                if (in_pub == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                result = read_file(&pub_data,&publen,in_pub);
				if(result == 0){
					printf("PUB FILE READING ERROR\n");
					exit(1);
				}
                break;
            case 'g':
                in_sig = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)in_sig, optarg);
                if (in_sig == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                result = read_file(&sig_data,&siglen,in_sig);
				if(result == 0){
					printf("SIGN FILE READING ERROR\n");
					exit(1);
				}
                break;            
            case '+':
                ifile = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)ifile, optarg);
                if (ifile == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
                    return 1;
                }
                result = read_file(&data,&datalen,ifile);
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
            case 'o':
                out_K = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)out_K, optarg);
                if (out_K == NULL) {
                    printf("Error: failed to allocate memory for master-key.\n");
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

    if( (e_flag + d_flag + s_flag + v_flag + k_flag + m_flag + x_flag != 1) ){
        fprintf(stderr, "Error: You must and can only choose one of these parameters : [ --sign --verify --kem --kdm --enc --dec --exchange].\n");
        exit(1);
    }
    if( x_flag == 1 ){
        if( init + resp == 0 ){
            fprintf(stderr, "Error: You must and can only play one role while key exchanging: [ --user-role=initiator | --user-role=responder].\n");
            exit(1);
        }
        if( check_flag == 1){

        }
    }

    fp12_t g1,g2,g3;
    fp12_null(g1);
    fp12_null(g2);
    fp12_null(g3);
    fp12_new(g1);
    fp12_new(g2);
    fp12_new(g3);


    ep_t C;
    ep_null(C);
    ep_new(C);

    ep_t Cb;
    ep_null(Cb);
    ep_new(Cb);

    bn_t ra;
    bn_null(ra);
    bn_new(ra);

    int ret;
    if(s_flag == 1){
        ep2_read_bin(sign_user.Ppubs,pub_data,publen);
        ep_read_bin(sign_user.ds,key_data,keylen);
        sm9_sign_init(&ctx);
	    sm9_sign_update(&ctx,data, datalen);
	    sm9_sign_finish(&ctx, &sign_user, out, &outlen);
        if(ofile != NULL){
            write_file(ofile,out,outlen);
        }
    }
    else if(v_flag == 1){
        ep2_read_bin(sign_user.Ppubs,pub_data,publen);
        sm9_verify_init(&ctx);
	    sm9_verify_update(&ctx, data, datalen);
	    if (sm9_verify_finish(&ctx, sig_data, siglen, &sign_user,(char *)user_id, idlen) != 1){
            printf("Verification Failure");
            return 1;
        }
        printf("Verified OK");
    }
    else if(e_flag == 1){
        ep_read_bin(enc_master.Ppube,pub_data,publen);
        sm9_encrypt(&enc_master, (char *)user_id, idlen, data, datalen, out, &outlen);
        if(ofile != NULL){
            write_file(ofile,out,outlen);
        }
    }
    else if(d_flag == 1){
        ep2_read_bin(enc_user.de,key_data,keylen);
        sm9_decrypt(&enc_user, (char *)user_id, idlen, data, datalen, out, &outlen);
        if(ofile != NULL){
            write_file(ofile,out,outlen);
        }
    }
    else if(k_flag == 1){
        //kem
        printf("publen is %d",publen);
        ep_read_bin(enc_master.Ppube,pub_data,publen);
        sm9_kem_encrypt(&enc_master, (char *)user_id, idlen, klen, kbuf, C);
        if(out_key != NULL){
            write_file(out_key,kbuf,klen);
        }
        if(ofile != NULL){
            outlen = 65;
            ep_write_bin(out,outlen,C,0);
            write_file(ofile,out,outlen);
        }

    }
    else if(m_flag == 1){
        //kdm
        format_bytes(stdout, 0, 0, "secret keydata", K_data, Klen);
        printf("\nKlen%d\n",Klen);
        format_bytes(stdout, 0, 0, "private keydata", key_data, keylen);
        printf("\nkeylen%d\n",keylen);
        ep2_read_bin(enc_user.de,key_data,keylen);
        ep_read_bin(C,data,datalen);

        sm9_kem_decrypt(&enc_user,(char *)user_id, idlen,C,Klen,K_data);
        if(out_key != NULL){
            write_file(out_key,K_data,Klen);
        }
    }
    else if( init == 1){
        // initiator
        ep_read_bin(enc_user.Ppube,pub_data,publen);      // masterpub
        ep2_read_bin(enc_user.de,key_data,keylen);        // user's private key
        sm9_exchange_A1(&enc_user,user_id,idlen,C,ra);

        ep_read_bin(Cb,K_data,Klen);                      // another user's temporary public key
        
        if(check_flag == 1){
            sm9_exchange_A2(&enc_user,C,Cb,ra,user_id,idlen,other_id,other_idlen,klen,kbuf,salen,sa,datalen,data);
            write_file(ofile,sa,salen);
        }
        else{
            sm9_exchange_A2_without_check(&enc_user,C,Cb,ra,user_id,idlen,other_id,other_idlen,klen,kbuf);
        }
        if(out_key != NULL){
            write_file(out_key,kbuf,klen);
        }
        if(out_K != NULL){
            outlen = 65;
            ep_write_bin(out,outlen,C,0);
            write_file(out_K,out,outlen);
        }
    }
    else{
        //resp == 0
        ep_read_bin(enc_user.Ppube,pub_data,publen);       // masterpub
        ep2_read_bin(enc_user.de,key_data,keylen);         // user's private key
        ep_read_bin(C,K_data,Klen);                        // another user's temporary public key
        if(check_flag == 1){
            sm9_exchange_B1(&enc_user,g1,g2,g3,C,Cb,other_id,other_idlen,user_id,idlen,klen,kbuf,salen,sa);
            sm9_exchange_B2(g1,g2,g3,C,Cb,other_id,other_idlen,user_id,idlen,datalen,data);
            write_file(ofile,sa,salen);
        }
        else{
            sm9_exchange_B1_without_check(&enc_user,g1,g2,g3,C,Cb,other_id,other_idlen,user_id,idlen,klen,kbuf);
        }
        if(out_key != NULL){
            write_file(out_key,kbuf,klen);
        }
        if(out_K != NULL){
            outlen = 65;
            ep_write_bin(out,outlen,Cb,0);
            write_file(out_K,out,outlen);
        }

    }

    ep_free(Cb);
    ep_free(C);
    fp12_free(g1);
    fp12_free(g2);
    fp12_free(g3);
    sign_master_key_free(&sign_master);
    enc_master_key_free(&enc_master);
    sign_user_key_free(&sign_user);
    enc_user_key_free(&enc_user);
    free(ifile);
    free(ofile);
    free(user_id);
    free(in_pub);
    free(in_sig);
    free(in_key);
    free(out_key);
    free(data);
    free(pub_data);
    free(key_data);
    free(sig_data);
    return 0;
}