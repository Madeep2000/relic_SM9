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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sm9.h"
#include "gmssl/error.h"
#include "debug.h"
#include <malloc.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

void test_sm9_sign_and_ver(){
	const char *id = "Alice";
	// data = "Chinese IBS standard"
	uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
	int idlen = 5;
	int datalen = 20;
	int j = 1;
	
	SM9_SIGN_KEY sign_key;
	SM9_SIGN_MASTER_KEY sign_master;

	sign_user_key_init(&sign_key);
	sign_master_key_init(&sign_master);

	SM9_SIGN_CTX ctx;
	//const char *id = "Alice";

	uint8_t sig[104];
	size_t siglen;
		
	sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_key);
	sm9_sign_init(&ctx);
	sm9_sign_update(&ctx,data, datalen);
	sm9_sign_finish(&ctx, &sign_key, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	sm9_verify_init(&ctx);
	sm9_verify_update(&ctx, data, datalen);
	if (sm9_verify_finish(&ctx, sig, siglen, &sign_key,(char *)id, idlen) != 1) goto err; ++j;
	format_bytes(stdout, 0, 0, "\nverified signature", sig, siglen);
	//write_file("output.txt",sig,siglen);

	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);

	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);
	error_print();
	return -1;
}

void test_sm9_sign_cmd(uint8_t data[],size_t datalen,char id[],size_t idlen){

	int j = 1;
	SM9_SIGN_KEY sign_key;
	SM9_SIGN_MASTER_KEY sign_master;

	sign_user_key_init(&sign_key);
	sign_master_key_init(&sign_master);

	SM9_SIGN_CTX ctx;
	//const char *id = "Alice";

	uint8_t sig[104];
	size_t siglen;

	char ks[] = "130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4";
	
	bn_read_str(sign_master.ks,ks,strlen(ks),16);

	//sm9_bn_t ks = {0x1F2DC5F4,0x348A1D5B,0x340F319F,0x80CE0B66,0x87E02CF4,0x45CB54C5,0x8459D785,0x0130E7};
	//bn_to_bn(sign_master.ks,ks);
	ep2_mul_gen(sign_master.Ppubs,sign_master.ks);

	sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_key);
	sm9_sign_init(&ctx);
	sm9_sign_update(&ctx,data, datalen);
	sm9_sign_finish(&ctx, &sign_key, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	sm9_verify_init(&ctx);
	sm9_verify_update(&ctx, data, datalen);
	if (sm9_verify_finish(&ctx, sig, siglen, &sign_master,(char *)id, idlen) != 1) goto err; ++j;
	format_bytes(stdout, 0, 0, "signature", sig, siglen);
	
	//write_file(outfile,sig,siglen);
	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);

	return 1;
err:
	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

void test_sm9_sign_cmdfile(uint8_t data[],size_t datalen,char id[],size_t idlen,char outfile[]){

	int j = 1;
	SM9_SIGN_KEY sign_key;
	SM9_SIGN_MASTER_KEY sign_master;
	SM9_SIGN_CTX ctx;
	//const char *id = "Alice";
	//uint8_t data[] = "Chinese IBS standard"
	uint8_t sig[104];
	size_t siglen;

	sign_user_key_init(&sign_key);
	sign_master_key_init(&sign_master);
	sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_key);
	sm9_sign_init(&ctx);
	sm9_sign_update(&ctx,data, datalen);
	
	sm9_sign_finish(&ctx, &sign_key, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);

	sm9_verify_init(&ctx);
	sm9_verify_update(&ctx, data, datalen);
	if (sm9_verify_finish(&ctx, sig, siglen, &sign_master,(char *)id, idlen) != 1) goto err; ++j;
	format_bytes(stdout, 0, 0, "\nverified signature", sig, siglen);
	
	write_file(outfile,sig,siglen);
	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);

	return 1;
err:
	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#include <stdint.h>
#include <getopt.h>

void print_usage(char *program_name) {
    printf("Usage: %s [-L plaintext_len] [-P plaintext] [-l id_len] [-i id] [-F infile.txt] [-f outfile.txt]\n", program_name);
    printf("Options:\n");
	printf("  -L plaintext_len       Specify plaintext_len (int)\n");
    printf("  -P plaintext           Specify plaintext (uint8_t[])\n");
	printf("  -l idlen               Specify idlen (int)\n");
    printf("  -i id                  Specify id (uint8_t[])\n");
	printf("  -f outfile.txt         Specify outputfile (char[])\n");
    printf("  -h                     Print this help message\n");
	printf("EXAMPLE: ./test_sm9_sign -L 20 -P \"Chinese IBS standard\" -l 5 -i \"Alice\" -f signature\n");
}

int main(int argc, char *argv[]) {
    /*int datalen = 0;
    int idlen = 0;
    uint8_t *data;
    char *id;
	char *ofile;
    int opt;
    while ((opt = getopt(argc, argv, "P:i:L:l:F:f:h")) != -1) {
        switch (opt) {
            case 'P':
                data = (uint8_t *)malloc((datalen) * sizeof(uint8_t));
				memcpy((uint8_t *)data, optarg,datalen);
                if (data == NULL) {
                    printf("Error: failed to allocate memory for plaintext.\n");
                    return 1;
                }
                // Parse data from optarg
                break;
            case 'i':
                id = (char *)malloc(idlen * sizeof(char));
				strcpy((char *)id, optarg);
                if (id == NULL) {
                    printf("Error: failed to allocate memory for id.\n");
                    return 1;
                }
                // Parse id from optarg
                break;
            case 'L':
                datalen = atoi(optarg);
                break;
            case 'l':
                idlen = atoi(optarg);
                break;
			case 'F':
                break;
			case 'f':
				ofile = (char *)malloc(strlen(optarg) * sizeof(char));
				strcpy((char *)ofile, optarg);
                if (ofile == NULL) {
                    printf("Error: failed to allocate memory for plaintext.\n");
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
    if (datalen <= 0 || idlen <= 0) {
		print_usage(argv[0]);
        printf("Error: datalen and idlen must be greater than 0.\n");
        return 1;
    }
	*/

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (pc_param_set_any() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	test_sm9_sign_and_ver();
	//test_sm9_sign_cmd(data,datalen,id,idlen);
	//test_sm9_sign_cmdfile(data,datalen,id,idlen,ofile);
	core_clean();

    //free(data);
    //free(id);

    return 0;
}

