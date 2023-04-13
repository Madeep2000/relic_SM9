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
#ifndef SM9_H
#define SM9_H

#include <stdio.h>
#include <omp.h>

#include "relic.h"

#include "gmssl/sm3.h"

#include "gmssl/error.h"
#include "gmssl/mem.h"
#include "gmssl/asn1.h"

fp_t SM9_ALPHA1, SM9_ALPHA2, SM9_ALPHA3, SM9_ALPHA4, SM9_ALPHA5;
fp2_t SM9_BETA;
#define SM9_N		"B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25"
#define SM9_HID_SIGN		0x01
#define SM9_HID_EXCH		0x02
#define SM9_HID_ENC		0x03


#define SM9_HASH1_PREFIX	0x01
#define SM9_HASH2_PREFIX	0x02

#define SM9_MAX_PLAINTEXT_SIZE 255
#define SM9_MAX_CIPHERTEXT_SIZE 367 

#define SM9_ENC_TYPE_XOR	0
#define SM9_ENC_TYPE_ECB	1
#define SM9_ENC_TYPE_CBC	2
#define SM9_ENC_TYPE_OFB	4
#define SM9_ENC_TYPE_CFB	8

typedef uint64_t sm9_bn_t[8];
typedef uint64_t sm9_barrett_bn_t[9];
typedef sm9_bn_t sm9_fn_t;

typedef struct {
	bn_t h;
	ep_t S;
} SM9_SIGNATURE;

typedef struct {
	ep_t ds;
	ep2_t Ppubs;
} SM9_SIGN_KEY;

typedef struct {
	ep2_t Ppubs; // Ppubs = ks * P2
	bn_t ks;     // sm9_fn_t
} SM9_SIGN_MASTER_KEY;

typedef struct {
	SM3_CTX sm3_ctx;
} SM9_SIGN_CTX;

typedef struct {
	ep_t Ppube; // Ppube = ke * P1
	bn_t ke;
} SM9_ENC_MASTER_KEY;

typedef struct {
	ep_t Ppube;
	ep2_t de;
} SM9_ENC_KEY;

void sm9_init();
void sm9_clean();
int write_file(char filename[],uint8_t output[],int output_size);
int read_file(char filename[], uint8_t **output, size_t *output_size);
//void master_key_init(SM9_SIGN_MASTER_KEY key);
//void master_key_free(SM9_SIGN_MASTER_KEY key);
//void user_key_init(SM9_SIGN_KEY key);
//void user_key_free(SM9_SIGN_KEY key);


// sm9 pairing and its update
void sm9_pairing(fp12_t r, const ep2_t Q, const ep_t P);
void sm9_pairing_fast(fp12_t r, const ep2_t Q, const ep_t P);
void sm9_pairing_fastest(fp12_t r, const ep2_t Q, const ep_t P);

// 运行arr_size次配对算法，使用threads_num个线程运行
void sm9_pairing_omp(fp12_t r_arr[], const ep2_t Q_arr[], const ep_t P_arr[], const size_t arr_size, const size_t threads_num);

// sm9 signature
int sm9_sign_init(SM9_SIGN_CTX *ctx);
int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen);
int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig);
int sm9_verify_init(SM9_SIGN_CTX *ctx);
int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,	const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen);

//sm9 crypto

#endif