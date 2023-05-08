/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
#include "../test/debug.h"

// for H1() and H2()
// h = (Ha mod (n-1)) + 1;  h in [1, n-1], n is the curve order, Ha is 40 bytes from hash
static const sm9_bn_t SM9_ONE = {1,0,0,0,0,0,0,0};
static const sm9_barrett_bn_t SM9_MU_N_MINUS_ONE = {0xdfc97c31, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001};
static const sm9_bn_t SM9_N_MINUS_ONE = {0xd69ecf24, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};


void sm9_init(){
	// beta   = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
	// alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
	// alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	// alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
	// alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333
	// alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686
	char beta[] = "6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D011";
	char alpha1[] = "3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B";
	char alpha2[] = "F300000002A3A6F2780272354F8B78F4D5FC11967BE65334";
	char alpha3[] = "6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D011";
	char alpha4[] = "F300000002A3A6F2780272354F8B78F4D5FC11967BE65333";
	char alpha5[] = "2D40A38CF6983351711E5F99520347CC57D778A9F8FF4C8A4C949C7FA2A96686";

	fp2_null(SM9_BETA);
	fp_null(SM9_ALPHA1);
	fp_null(SM9_ALPHA2);
	fp_null(SM9_ALPHA3);
	fp_null(SM9_ALPHA4);
	fp_null(SM9_ALPHA5);

	fp2_new(SM9_BETA);
	fp_new(SM9_ALPHA1);
	fp_new(SM9_ALPHA2);
	fp_new(SM9_ALPHA3);
	fp_new(SM9_ALPHA4);
	fp_new(SM9_ALPHA5);

	fp_read_str(SM9_BETA[0], beta, strlen(beta), 16);
	fp_set_dig(SM9_BETA[1], 0);

	fp_read_str(SM9_ALPHA1, alpha1, strlen(alpha1), 16);
	fp_read_str(SM9_ALPHA2, alpha2, strlen(alpha2), 16);
	fp_read_str(SM9_ALPHA3, alpha3, strlen(alpha3), 16);
	fp_read_str(SM9_ALPHA4, alpha4, strlen(alpha4), 16);
	fp_read_str(SM9_ALPHA5, alpha5, strlen(alpha5), 16);
}

void sm9_clean(){
	fp2_free(SM9_BETA);
	fp_free(SM9_ALPHA1);
	fp_free(SM9_ALPHA2);
	fp_free(SM9_ALPHA3);
	fp_free(SM9_ALPHA4);
	fp_free(SM9_ALPHA5);
}

//把filename文件的内容读到output里面
//FIX ME
int read_file(uint8_t **output, size_t *output_size,char filename[]) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("FILE OPEN ERROR\n");
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    *output_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *output = (uint8_t *)malloc(*output_size * sizeof(uint8_t));
    if (*output == NULL) {
        printf("Error: failed to allocate memory\n");
        fclose(fp);
        return 0;
    }

    fread(*output, sizeof(uint8_t), *output_size, fp);
    fclose(fp);
    return 1;
}

// replace read_file
int read_file_t(uint8_t output[],int output_size,char filename[]){
	FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("FILE OPEN ERROR\n");
        return 0;
    }
	size_t n_read = fread(output,sizeof(uint8_t),output_size,fp);
	if (n_read != output_size) {
        printf("Error: failed to read file\n");
        fclose(fp);
        return 0;
    }
	fclose(fp);
	return 1;
}

//把output的内容写到filename文件里面
int write_file(char filename[],uint8_t output[],int output_size){

	FILE *fp=fopen(filename,"wb");
	if(fp == NULL){
		printf("FILE OPEN ERROR!");
		return 0;
	}
	size_t n_write = fwrite(output,sizeof(uint8_t),output_size,fp);
	if (n_write != output_size) {
        printf("Error: failed to write file\n");
        fclose(fp);
        return 0;
    }
 	fclose(fp);
	return 1;

}

//default ks
void sign_master_key_init(SM9_SIGN_MASTER_KEY *key){
	bn_null(key->ks);
	bn_new(key->ks);
	ep2_null(key->Ppubs);
	ep2_new(key->Ppubs);
	char ks[] = "130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4";
	bn_read_str(key->ks,ks,strlen(ks),16);
	ep2_mul_gen(key->Ppubs,key->ks);
	return;
}


//set ks in binary array
void sign_master_key_set(SM9_SIGN_MASTER_KEY *key,uint8_t ks[],int kslen){
	bn_null(key->ks);
	bn_new(key->ks);
	ep2_null(key->Ppubs);
	ep2_new(key->Ppubs);

	bn_read_bin(key->ks,ks,kslen);
	ep2_mul_gen(key->Ppubs,key->ks);

	return;
}

//read ks in printable array
void sign_master_key_read(SM9_SIGN_MASTER_KEY *key,char ks[],int kslen,int radix){
	bn_null(key->ks);
	bn_new(key->ks);
	ep2_null(key->Ppubs);
	ep2_new(key->Ppubs);

	bn_read_str(key->ks,ks,kslen,radix);
	ep2_mul_gen(key->Ppubs,key->ks);

	return;
}

//random ks
void sign_master_key_gen(SM9_SIGN_MASTER_KEY *key){
	
	
	bn_null(key->ks);
	bn_new(key->ks);
	ep2_null(key->Ppubs);
	ep2_new(key->Ppubs);

	bn_t N;
    bn_null(N);
    bn_new(N);
    bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);

	bn_rand(key->ks,RLC_POS,256);
	while((bn_cmp_dig(key->ks,1) == -1) || (bn_cmp(key->ks,N) == 1)){
		bn_rand(key->ks,RLC_POS,256);
	}
	ep2_mul_gen(key->Ppubs,key->ks);

	bn_free(N);
	return;

}

void sign_master_key_free(SM9_SIGN_MASTER_KEY *key){
	bn_free(key->ks);
	ep2_free(key->Ppubs);
	return;
}

void sign_user_key_init(SM9_SIGN_KEY *key){
	ep_null(key->ds);
	ep_new(key->ds);
	ep2_null(key->Ppubs);
	ep2_new(key->Ppubs);
	return;
}

void sign_user_key_free(SM9_SIGN_KEY *key){
	ep_free(key->ds);
	ep2_free(key->Ppubs);
	return;
}


void enc_user_key_init(SM9_ENC_KEY *key){
	ep_null(key->Ppube);
	ep2_null(key->de);
	ep_new(key->Ppube);
	ep2_new(key->de);
	return;
}

void enc_user_key_free(SM9_ENC_KEY *key){
	ep_free(key->Ppube);
	ep2_free(key->de);
	return;
}

//default ke
void enc_master_key_init(SM9_ENC_MASTER_KEY *tem){
	bn_null(tem->ke);
	bn_new(tem->ke);
	ep_null(tem->Ppube);
	ep_new(tem->Ppube);
	//char ke[] = "2E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F";
	char ke[] = "1EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22";
	bn_read_str(tem->ke,ke,strlen(ke),16);
	ep_mul_gen(tem->Ppube,tem->ke);
	return;
}

//set ke in binary array
void enc_master_key_set(SM9_ENC_MASTER_KEY *tem,uint8_t ke[],int kelen){

	bn_null(tem->ke);
	bn_new(tem->ke);
	ep_null(tem->Ppube);
	ep_new(tem->Ppube);
	bn_read_bin(tem->ke,ke,kelen);
	ep_mul_gen(tem->Ppube,tem->ke);
	return;
}


//read ke in a printable(char) array
void enc_master_key_read(SM9_ENC_MASTER_KEY *tem,char *ke,int kelen,int radix){

	bn_null(tem->ke);
	bn_new(tem->ke);
	ep_null(tem->Ppube);
	ep_new(tem->Ppube);
	bn_read_str(tem->ke,ke,kelen,radix);
	
	ep_mul_gen(tem->Ppube,tem->ke);
	return;
}

// random ke
void enc_master_key_gen(SM9_ENC_MASTER_KEY *tem){
	bn_null(tem->ke);
	bn_new(tem->ke);
	ep_null(tem->Ppube);
	ep_new(tem->Ppube);

	bn_t N;
    bn_null(N);
    bn_new(N);
    bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);

	bn_rand(tem->ke,RLC_POS,256);
	while((bn_cmp_dig(tem->ke,1) == -1) || (bn_cmp(tem->ke,N) == 1)){
		bn_rand(tem->ke,RLC_POS,256);
	}
	ep_mul_gen(tem->Ppube,tem->ke);
	return;
}

void enc_master_key_free(SM9_ENC_MASTER_KEY *tem){
	bn_free(tem->ke);
	ep_free(tem->Ppube);
	return ;
}

static void fp_to_bn(sm9_bn_t a, fp_t b){
	uint8_t tmp_buff[32];
	fp_write_bin(tmp_buff, 32, b);
	uint32_t tmp32;
	for (size_t i = 0; i < 8; i++)
	{	
		tmp32 = 0;
		for (size_t j = 0; j < 4; j++)
		{
			tmp32 += (tmp_buff[i*4+j] << (3-j));
		}
		a[7-i] = tmp32;
	}
}

/*input: sm9_bn_t 
output: fp_t
*/
static void bn_to_fp(fp_t a, sm9_bn_t b){
	uint8_t tmp_buff[32];
	for (size_t i = 0; i < 8; i++)
	{
		for (size_t j = 0; j < 4; j++)
		{
			tmp_buff[31-(i*4+j)] = (b[i]>>(j*8))&0xff;
		}
	}
	fp_read_bin(a, tmp_buff, 32);
}

void bn_to_bn(bn_t a, sm9_bn_t b){
	uint8_t tmp_buff[32];
	for (size_t i = 0; i < 8; i++)
	{
		for (size_t j = 0; j < 4; j++)
		{
			tmp_buff[31-(i*4+j)] = (b[i]>>(j*8))&0xff;
		}
	}
	bn_read_bin(a, tmp_buff, 32);
}


//ep_t *P
int sm9_point_to_uncompressed_octets(const ep_t P, uint8_t octets[65])
{
	// fp_t x;
	// fp_t y;
	// sm9_point_get_xy(P, x, y);
	octets[0] = 0x04;
	ep_write_bin(octets, 64, P, 0);
	// sm9_bn_to_bytes(x, octets + 1);
	// sm9_bn_to_bytes(y, octets + 32 + 1);
	return 1;
}

//ep_t *P
int sm9_point_from_uncompressed_octets(const ep_t P, const uint8_t octets[65])
{
	if (octets[0] != 0x04) {
		error_print();
		return -1;
	}
	memset(P, 0, sizeof(*P));
	ep_set_infty(P);
	ep_write_bin(octets, 64, P, 0);
	//sm9_bn_from_bytes(P->X, octets + 1);
	//sm9_bn_from_bytes(P->Y, octets + 32 + 1);
	//fp_set_dig(P->z , 1);
	//sm9_fp_set_one(P->Z);
	
	if(!ep_on_curve(P)){
		error_print();
		return -1;
	}
	/*if (!sm9_point_is_on_curve(P)) {
		error_print();
		return -1;
	}*/
	return 1;
}


static size_t bn_to_bits(const sm9_bn_t a, char bits[256])
{	
	int lowest_bit_index;
	int i, j;
	char *tmp = bits;
	for (i = 7; i >= 0; i--) {
		uint32_t w = a[i];
		for (j = 0; j < 32; j++) {
			*bits++ = (w & 0x80000000) ? '1' : '0';
			w <<= 1;
		}
	}
	// *bits = 0;
	for (size_t i = 0; i < 256; i++)
	{
		if (tmp[i] == '1')
		{
			return i;
		}
	}
	// printf("bits\n%s\n", tmp);
	// printf("highest_bit_index = %d\n", highest_bit_index);
	// return highest_bit_index;
}

// a*k = (a1, a2)*k = (a1*k, a2*k)
static void fp2_mul_fp(fp2_t r, const fp2_t a, const fp_t k)
{
	fp_mul(r[0], a[0], k);
	fp_mul(r[1], a[1], k);
}

static void fp2_conjugate(fp2_t r, const fp2_t a)
{
	fp_copy(r[0], a[0]);
	fp_neg(r[1], a[1]);
}

static void fp2_mul_u(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_t r0, r1, t;

	fp_null(r0);
	fp_null(r1);
	fp_null(t);

	fp_new(r0);
	fp_new(r1);
	fp_new(t);

	// r0 = -2 * (a0 * b1 + a1 * b0)
	fp_mul(r0, a[0], b[1]);
	fp_mul(t,  a[1], b[0]);
	fp_add(r0, r0, t);
	fp_dbl(r0, r0);
	fp_neg(r0, r0);

	// r1 = a0 * b0 - 2 * a1 * b1
	fp_mul(r1, a[0], b[0]);
	fp_mul(t, a[1], b[1]);
	fp_dbl(t, t);
	fp_sub(r1, r1, t);

	fp_copy(r[0], r0);
	fp_copy(r[1], r1);

	fp_free(r0);
	fp_free(r1);
	fp_free(t);
}

static void fp2_sqr_u(fp2_t r, const fp2_t a)
{
	fp_t r0, r1, t;

	fp_null(r0);
	fp_null(r1);
	fp_null(t);

	fp_new(r0);
	fp_new(r1);
	fp_new(t);

	// r0 = -4 * a0 * a1
	fp_mul(r0, a[0], a[1]);
	fp_dbl(r0, r0);
	fp_dbl(r0, r0);
	fp_neg(r0, r0);

	// r1 = a0^2 - 2 * a1^2
	fp_sqr(r1, a[0]);
	fp_sqr(t, a[1]);
	fp_dbl(t, t);
	fp_sub(r1, r1, t);

	fp_copy(r[0], r0);
	fp_copy(r[1], r1);

	fp_free(r0);
	fp_free(r1);
	fp_free(t);
}

static void fp4_sqr_v(fp4_t r, const fp4_t a)
{
	fp2_t r0, r1, t;
	fp2_null(r0);
	fp2_null(r1);
	fp2_null(t);

	fp2_new(r0);
	fp2_new(r1);
	fp2_new(t);

	fp2_mul_u(t, a[0], a[1]);
	fp2_dbl(r0, t);

	fp2_sqr(r1, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);

	fp2_free(r0);
	fp2_free(r1);
	fp2_free(t);
}

static void fp4_mul_v(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_t r0, r1, t;
	fp2_null(r0);
	fp2_null(r1);
	fp2_null(t);

	fp2_new(r0);
	fp2_new(r1);
	fp2_new(t);

	fp2_mul_u(r0, a[0], b[1]);
	fp2_mul_u(t, a[1], b[0]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);

	fp2_free(r0);
	fp2_free(r1);
	fp2_free(t);
}

static void fp4_mul_fp(fp4_t r, const fp4_t a, const fp_t k)
{
	fp2_mul_fp(r[0], a[0], k);
	fp2_mul_fp(r[1], a[1], k);
}

/* 
void sm9_fp2_u(sm9_fp2_t r, const sm9_fp2_t a){
	sm9_fp_copy(r[1], a[0]);
	sm9_fp_dbl(r[0], a[1]);
	sm9_fp_neg(r[0], r[0]);
}
即fp2_mul_nor(fp2_t c,fp2_t a)
*/

/* r = a*v, 即 r = a0v + a1*u  
void sm9_fp4_v(sm9_fp4_t r, const sm9_fp4_t a){
	sm9_fp2_copy(r[1], a[0]);
	sm9_fp2_u(r[0], a[1]);
}
即 fp4_mul_art(fp4_t r,fp4_t a)
*/

/* (a0+a1*v)*b*v = a1*b*u + a0*b*v */
void fp4_mul_fp2_v(fp4_t r, const fp4_t a, const fp2_t b){
	fp2_mul(r[0], a[1], b);
	fp2_mul_nor(r[0],r[0]);
	fp2_mul(r[1], a[0], b);
}

void fp4_mul_fp2(fp4_t r, const fp4_t a, const fp2_t b){
	fp2_mul(r[0], a[0], b);
	fp2_mul(r[1], a[1], b);
}

static void fp4_conjugate(fp4_t r, const fp4_t a)
{
	fp2_copy(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

void fp12_mul_t1(fp12_t r, const fp12_t a, const fp12_t b)
{
	fp4_t r0, r1, r2, t;

	fp4_null(r0);
	fp4_null(r1);
	fp4_null(r2);
	fp4_null(t);

	fp4_new(r0);
	fp4_new(r1);
	fp4_new(r2);
	fp4_new(t);

	fp4_mul(r0, a[0][0], b[0][0]);
	fp4_mul_v(t, a[0][2], b[1][1]);
	fp4_add(r0, r0, t);
	fp4_mul_v(t, a[1][1], b[0][2]);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0][0], b[0][2]);
	fp4_mul(t, a[0][2], b[0][0]);
	fp4_add(r1, r1, t);
	fp4_mul_v(t, a[1][1], b[1][1]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0][0], b[1][1]);
	fp4_mul(t, a[0][2], b[0][2]);
	fp4_add(r2, r2, t);
	fp4_mul(t, a[1][1], b[0][0]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0][0], r0);
	fp4_copy(r[0][2], r1);
	fp4_copy(r[1][1], r2);

	fp4_free(r0);
	fp4_free(r1);
	fp4_free(r2);
	fp4_free(t);
}

static void fp12_mul_unr_t(dv12_t c, fp12_t a, fp12_t b) {
	dv4_t u0, u1, u2, u3, u4;
	fp4_t t0, t1;

	dv4_null(u0);
	dv4_null(u1);
	dv4_null(u2);
	dv4_null(u3);
	dv4_null(u4);
	fp4_null(t0);
	fp4_null(t1);

	RLC_TRY {
		dv4_new(u0);
		dv4_new(u1);
		dv4_new(u2);
		dv4_new(u3);
		dv4_new(u4);
		fp4_new(t0);
		fp4_new(t1);

		/* Karatsuba algorithm. */

		/* u0 = a_0 * b_0. */
		fp4_mul_unr(u0, a[0][0], b[0][0]);
		/* u1 = a_1 * b_1. */
		fp4_mul_unr(u1, a[0][2], b[0][2]);
		/* u2 = a_2 * b_2. */
		fp4_mul_unr(u2, a[1][1], b[1][1]);

		fp4_add(t0, a[0][2], a[1][1]);
		fp4_add(t1, b[0][2], b[1][1]);
		/* u3 = ( a1 + a2 )*( b1 + b2 ) */
		fp4_mul_unr(u3, t0, t1);

		/* u3 = (a1+a2)*(b1+b2) - a1*b1 - a2*b2 = a1*b2 + a2*b1 */
		fp2_subc_low(u3[0], u3[0], u1[0]);
		fp2_subc_low(u3[0], u3[0], u2[0]);
		fp2_subc_low(u3[1], u3[1], u1[1]);
		fp2_subc_low(u3[1], u3[1], u2[1]);

		/* c0 = ( a2*b1 + a1*b2 ) * v + a0*b0 */
		fp2_nord_low(u4[0], u3[1]);
		fp2_addc_low(c[0][0], u4[0], u0[0]);
		fp2_addc_low(c[0][1], u3[0], u0[1]);


		fp4_add(t0, a[0][0], a[0][2]);
		fp4_add(t1, b[0][0], b[0][2]);
		/* u4 = ( a0 + a1 ) * ( b0 + b1 ) */
		fp4_mul_unr(u4, t0, t1);

		/* u4 = ( a0 + a1 ) * ( b0 + b1 ) - a0*b0 - a1*b1 = a0*b1 + a1*b0 */
		for (int i = 0; i < 2; i++) {
			fp2_subc_low(u4[i], u4[i], u0[i]);
			fp2_subc_low(u4[i], u4[i], u1[i]);
		}
		/* c1 = a2*b2*v + a0*b1 + a1*b0 */
		fp2_nord_low(u3[0], u2[1]);
		fp2_addc_low(c[0][2], u4[0], u3[0]);
		fp2_addc_low(c[1][0], u4[1], u2[0]);



		fp4_add(t0, a[0][0], a[1][1]);
		fp4_add(t1, b[0][0], b[1][1]);
		/* u4 = (a0+a2)*(b0+b2) */
		fp4_mul_unr(u4, t0, t1);

		/* c2 = (a0+a2)*(b0+b2) - a0*b0 - a2*b2 + a1b1 = a0b2 + a2b0 + a1b1 */
		for (int i = 0; i < 2; i++) {
			fp2_subc_low(u4[i], u4[i], u0[i]);
			fp2_addc_low(u4[i],u4[i],u1[i]);
			fp2_subc_low(c[1][1+i], u4[i], u2[i]);
		}

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv4_free(u0);
		dv4_free(u1);
		dv4_free(u2);
		dv4_free(u3);
		dv4_free(u4);
		fp4_free(t0);
		fp4_free(t1);
	}
}

void fp12_mul_t(fp12_t c, fp12_t a, fp12_t b) {
	dv12_t t;

	dv12_null(t);

	RLC_TRY {
		dv12_new(t);
		fp12_mul_unr_t(t, a, b);
		for (int i = 0; i < 3; i++) {
			fp2_rdcn_low(c[0][i], t[0][i]);
			fp2_rdcn_low(c[1][i], t[1][i]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv12_free(t);
	}
}


/* f is normal fp12_t ,g is a sparse fp12_t, g = g0 + g2'w^2, g0 = g0' + g3'w^3，g0',g1',g3' all defined in fp2
Multiplicative twist curve 乘扭曲线下的稀疏乘法
*/
void fp12_mul_sparse(fp12_t h, const fp12_t f, const fp12_t g){
	fp4_t t0, t1, u0, u1, u2, t, h0, h1, h2;

	// 1. t0 = f0*g0
	fp4_mul(t0, f[0][0], g[0][0]);

	// 2. t1 = Fp4SparseMul(f2, g2')
	fp4_mul_fp2(t1, f[1][1], g[1][1]);

	// 3. u0 = Fp4SparseMul(f1+f2, g2')
	fp4_add(u0, f[0][2], f[1][1]);
	fp4_mul_fp2(u0, u0, g[1][1]);

	// 4. u1 = (f0+f2)*(g0+g2')
	fp4_copy(t, g[0][0]);
	fp2_add(t[0], t[0], g[1][1]);  // t = (g0+g2')
	fp4_add(u1, f[0][0], f[1][1]);  // u1 = (f0+f2)
	fp4_mul(u1, u1, t);

	// 5. u2 = (f0+f1)*g0
	fp4_add(u2, f[0][0], f[0][2]);
	fp4_mul(u2, u2, g[0][0]);

	// 6. h0 = t0 + (u0 - t1)v
	fp4_sub(t, u0, t1);
	fp4_mul_art(h[0][0], t);  // h0 = (u0 - t1)v
	fp4_add(h[0][0], t0, h[0][0]);

	// 7. h1 = u2 - t0 + t1v
	fp4_mul_art(h[0][2], t1);  // h1 = t1v
	fp4_add(h[0][2], h[0][2], u2);
	fp4_sub(h[0][2], h[0][2], t0);

	// 8. h2 = u1 - t0 - t1
	fp4_sub(h[1][1], u1, t0);
	fp4_sub(h[1][1], h[1][1], t1);
}

//f is normal fp12_t ,g is a sparse fp12_t, g = g0 + g2'w^2, g0 = g0' + g3'w^3，g0',g1',g3' all defined in fp2

void fp12_mul_sparse_t(fp12_t c, const fp12_t f, const fp12_t l){
	fp4_t t2, t1,c1,c2,c0;

	//1. t1 = f_2*l_0
	fp4_mul_fp2(t1,f[1][1],l[0][0]);
	
	//2. t2 = f_0*l_0
	fp4_mul(t2,f[0][0],l[0][0]);

	//3. c0 = f1*l1
	fp4_mul(c0,f[0][2],l[1][1]);

	//4. c0 = c0*v
	fp4_mul_art(c0,c0);

	//5. c0 = c0+t2
	fp4_add(c0,c0,t2);

	//6. c1 = f1*l0
	fp4_mul(c0,f[0][2],l[0][0]);

	//7. c2=t1*v
	fp4_mul_art(c2,t1);

	//8. c1 = c1+c2
	fp4_add(c1,c1,c2);

	//9. t2=t1+t2
	fp4_add(t2,t1,t2);

	//10. t1=f0+f2
	fp4_add(t1,f[0][0],f[1][1]);

	//11. c2=l0+l1
	fp4_add(c2,l[0][0],l[1][1]);

	//12. c2=t1*c2
	fp4_mul(c2,t1,c2);

	//13. c2 = c2 - t2
	fp4_sub(c2,c2,t2);
	fp4_copy(c[0][0],c0);
	fp4_copy(c[0][2],c1);
	fp4_copy(c[1][1],c2);

}

void fp12_mul_dxs_t(fp12_t c,fp12_t a,fp12_t b){
	fp4_t t0, t1, t2, t3, t4;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp4_mul(t0,a[0][0],b[0][0]);
		fp4_add(t3,a[0][2],a[1][1]);
		fp4_add(t4,a[0][0],a[0][2]);

		if (fp4_is_zero(b[1][1])) {
			/* t1 = a_1 * b_1. */
			fp8_mul(t1, a[0][2], b[0][2]);
			/* b_2 = 0. */

			fp4_mul(t3, t3, b[0][2]);
			fp4_sub(t3, t3, t1);
			fp4_mul_art(t3, t3);
			fp4_add(t3, t3, t0);

			fp4_add(t2, b[0][0], b[0][2]);
			fp4_mul(t4, t4, t2);
			fp4_sub(t4, t4, t0);
			fp4_sub(c[0][2], t4, t1);

			fp4_add(t4, a[0][0], a[1][1]);
			fp4_mul(c[1][1], t4, b[0][0]);
			fp4_sub(c[1][1], c[1][1], t0);
			fp4_add(c[1][1], c[1][1], t1);
		} else {
			/* b_1 = 0. */
			/* t2 = a_2 * b_2. */
			fp4_mul(t1, a[1][1], b[1][1]);

			fp4_mul(t3, t3, b[1][1]);
			fp4_sub(t3, t3, t1);
			fp4_mul_art(t3, t3);
			fp4_add(t3, t3, t0);

			fp4_mul(t4, t4, b[0][0]);
			fp4_sub(t4, t4, t0);
			fp4_mul_art(t2, t1);
			fp4_add(c[0][2], t4, t2);

			fp4_add(t4, a[0][0], a[1][1]);
			fp4_add(t2, b[0][0], b[1][1]);
			fp4_mul(c[1][1], t4, t2);
			fp4_sub(c[1][1], c[1][1], t0);
			fp4_sub(c[1][1], c[1][1], t1);
		}
		
		fp4_copy(c[0][0], t3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
		fp4_free(t3);
		fp4_free(t4);
	}
}



// r = (a0 + a1*w + a2*w^2)*b3'w^3，其中b3'是fp2上的元素，也就是b0中的高位fp2，即b3'*w^3 = b3'*v
void fp12_mul_sparse2(fp12_t r, fp12_t a, fp12_t b){
	fp4_mul_fp2_v(r[0][0], a[0][0], b[0][1]);
	fp4_mul_fp2_v(r[0][2], a[0][2], b[0][1]);
	fp4_mul_fp2_v(r[1][1], a[1][1], b[0][1]);
}

// as same as conjugate in Fp12
void fp12_inv_cyc_t(fp12_t c, fp12_t a) {
	fp2_copy(c[0][0],a[0][0]);
	fp2_copy(c[1][1],a[1][1]);
	fp2_copy(c[1][0],a[1][0]);

	fp2_neg(c[0][2],a[0][2]);
	fp2_neg(c[0][1],a[0][1]);
	fp2_neg(c[1][2],a[1][2]);
}

void fp12_inv_t(fp12_t r, fp12_t a){
	RLC_TRY {
	if (fp4_is_zero(a[1][1])) {
		fp4_t k, t;

		fp4_null(k);
		fp4_null(t);

		fp4_new(k);
		fp4_new(t);

		fp4_sqr(k, a[0][0]);
		fp4_mul(k, k, a[0][0]);
		fp4_sqr(t, a[0][2]);
		fp4_mul_art(t,t);
		fp4_mul(t, t, a[0][2]);
		fp4_add(k, k, t);
		fp4_inv(k, k);

		fp4_sqr(r[1][1], a[0][2]);
		fp4_mul(r[1][1], r[1][1], k);

		fp4_mul(r[0][2], a[0][0], a[0][2]);
		fp4_mul(r[0][2], r[0][2], k);
		fp4_neg(r[0][2], r[0][2]);

		fp4_sqr(r[0][0], a[0][0]);
		fp4_mul(r[0][0], r[0][0], k);

		fp4_free(k);
		fp4_free(t);
	} else {
		fp4_t t0, t1, t2, t3;

		fp4_null(t0);
		fp4_null(t1);
		fp4_null(t2);
		fp4_null(t3);

		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);

		fp4_sqr(t0, a[0][2]);
		fp4_mul(t1, a[0][0], a[1][1]);
		fp4_sub(t0, t0, t1);

		fp4_mul(t1, a[0][0], a[0][2]);
		fp4_sqr(t2, a[1][1]);
		fp4_mul_art(t2,t2);
		fp4_sub(t1, t1, t2);

		fp4_sqr(t2, a[0][0]);
		fp4_mul(t3, a[0][2], a[1][1]);
		fp4_mul_art(t3,t3);
		fp4_sub(t2, t2, t3);

		fp4_sqr(t3, t1);
		fp4_mul(r[0][0], t0, t2);
		fp4_sub(t3, t3, r[0][0]);
		fp4_inv(t3, t3);
		fp4_mul(t3, a[1][1], t3);

		fp4_mul(r[0][0], t2, t3);

		fp4_mul(r[0][2], t1, t3);
		fp4_neg(r[0][2], r[0][2]);

		fp4_mul(r[1][1], t0, t3);
	
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
		fp4_free(t3);
	}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(v0);
		fp4_free(v1);
		fp4_free(v2);
		fp4_free(t0);
	}

}



static void fp12_sqr_unr_t(dv12_t c, fp12_t a) {
	fp4_t t0, t1;
	dv4_t u0, u1, u2, u3, u4;

	fp4_null(t0);
	fp4_null(t1);
	dv4_null(u0);
	dv4_null(u1);
	dv4_null(u2);
	dv4_null(u3);
	dv4_null(u4);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		dv4_new(u0);
		dv4_new(u1);
		dv4_new(u2);
		dv4_new(u3);
		dv4_new(u4);

		/* a0 = (a00, a01). */
		/* a1 = (a02, a10). */
		/* a2 = (a11, a12). */

		/* (t0,t1) = a0^2 */
		fp2_copy(t0[0], a[0][0]);
		fp2_copy(t0[1], a[0][1]);
		fp4_sqr_unr(u0, t0);

		/* (t2,t3) = 2 * a1 * a2 */
		fp2_copy(t0[0], a[0][2]);
		fp2_copy(t0[1], a[1][0]);
		fp2_copy(t1[0], a[1][1]);
		fp2_copy(t1[1], a[1][2]);
		fp4_mul_unr(u1, t0, t1);
		fp2_addc_low(u1[0], u1[0], u1[0]);
		fp2_addc_low(u1[1], u1[1], u1[1]);

		/* (t4,t5) = a2^2. */
		fp4_sqr_unr(u2, t1);

		/* c2 = a0 + a2. */
		fp2_addm_low(t1[0], a[0][0], a[1][1]);
		fp2_addm_low(t1[1], a[0][1], a[1][2]);

		/* (t6,t7) = (a0 + a2 + a1)^2. */
		fp2_addm_low(t0[0], t1[0], a[0][2]);
		fp2_addm_low(t0[1], t1[1], a[1][0]);
		fp4_sqr_unr(u3, t0);

		/* c2 = (a0 + a2 - a1)^2. */
		fp2_subm_low(t0[0], t1[0], a[0][2]);
		fp2_subm_low(t0[1], t1[1], a[1][0]);
		fp4_sqr_unr(u4, t0);

		/* c2 = (c2 + (t6,t7))/2. */
#ifdef RLC_FP_ROOM
		fp2_addd_low(u4[0], u4[0], u3[0]);
		fp2_addd_low(u4[1], u4[1], u3[1]);
#else
		fp2_addc_low(u4[0], u4[0], u3[0]);
		fp2_addc_low(u4[1], u4[1], u3[1]);
#endif
		fp_hlvd_low(u4[0][0], u4[0][0]);
		fp_hlvd_low(u4[0][1], u4[0][1]);
		fp_hlvd_low(u4[1][0], u4[1][0]);
		fp_hlvd_low(u4[1][1], u4[1][1]);

		/* (t6,t7) = (t6,t7) - c2 - (t2,t3). */
		fp2_subc_low(u3[0], u3[0], u4[0]);
		fp2_subc_low(u3[1], u3[1], u4[1]);
		fp2_subc_low(u3[0], u3[0], u1[0]);
		fp2_subc_low(u3[1], u3[1], u1[1]);

		/* c2 = c2 - (t0,t1) - (t4,t5). */
		fp2_subc_low(u4[0], u4[0], u0[0]);
		fp2_subc_low(u4[1], u4[1], u0[1]);
		fp2_subc_low(c[1][1], u4[0], u2[0]);
		fp2_subc_low(c[1][2], u4[1], u2[1]);

		/* c1 = (t6,t7) + (t4,t5) * E. */
		fp2_nord_low(u4[1], u2[1]);
		fp2_addc_low(c[0][2], u3[0], u4[1]);
		fp2_addc_low(c[1][0], u3[1], u2[0]);

		/* c0 = (t0,t1) + (t2,t3) * E. */
		fp2_nord_low(u4[1], u1[1]);
		fp2_addc_low(c[0][0], u0[0], u4[1]);
		fp2_addc_low(c[0][1], u0[1], u1[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		dv4_free(u0);
		dv4_free(u1);
		dv4_free(u2);
		dv4_free(u3);
		dv4_free(u4);
	}
}

void fp12_sqr_t(fp12_t c, const fp12_t a) {
	dv12_t t;

	dv12_null(t);

	RLC_TRY {
		dv12_new(t);
		fp12_sqr_unr_t(t, a);
		for (int i = 0; i < 3; i++) {
			fp2_rdcn_low(c[0][i], t[0][i]);
			fp2_rdcn_low(c[1][i], t[1][i]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv12_free(t);
	}
}

static void fp12_sqr_t1(fp12_t r, const fp12_t a)
{
	fp4_t r0, r1, r2, t;

	fp4_null(r0);
	fp4_null(r1);
	fp4_null(r2);
	fp4_null(t);

	fp4_new(r0);
	fp4_new(r1);
	fp4_new(r2);
	fp4_new(t);

	fp4_sqr(r0, a[0][0]);
	fp4_mul_v(t, a[0][2], a[1][1]);
	fp4_dbl(t, t);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0][0], a[0][2]);
	fp4_dbl(r1, r1);
	fp4_sqr_v(t, a[1][1]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0][0], a[1][1]);
	fp4_dbl(r2, r2);
	fp4_sqr(t, a[0][2]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0][0], r0);
	fp4_copy(r[0][2], r1);
	fp4_copy(r[1][1], r2);

	fp4_free(r0);
	fp4_free(r1);
	fp4_free(r2);
	fp4_free(t);
}

static void fp12_set(fp12_t r, const fp4_t a0, const fp4_t a1, const fp4_t a2)
{
	fp4_copy(r[0][0], a0);
	fp4_copy(r[0][2], a1);
	fp4_copy(r[1][1], a2);
}

void fp12_sqr_pck_t(fp12_t c, fp12_t a) {
	fp2_t t0, t1, t2;
	dv2_t u0, u1, u2, u3;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	dv2_null(u0);
	dv2_null(u1);
	dv2_null(u2);
	dv2_null(u3);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);

		fp2_sqrn_low(u0, a[1][1]);
		fp2_sqrn_low(u1, a[1][2]);
		fp2_addm_low(t0, a[1][1], a[1][2]);
		fp2_sqrn_low(u2, t0);

		fp2_addc_low(u3, u0, u1);
		fp2_subc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);

		fp2_addm_low(t1, a[0][2], a[1][0]);
		fp2_sqrm_low(t2, t1);
		fp2_sqrn_low(u2, a[0][2]);

		fp2_norm_low(t1, t0);
		fp2_addm_low(t0, t1, a[0][2]);
		fp2_dblm_low(t0, t0);
		fp2_addm_low(c[0][2], t0, t1);

		fp2_norh_low(u3, u1);
		fp2_sqrn_low(u1, a[1][0]);
		fp2_addc_low(u3, u0, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[1][0]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[1][0], t1, t0);

		fp2_addc_low(u0, u2, u1);
		fp2_rdcn_low(t0, u0);
		fp2_subm_low(t0, t2, t0);
		fp2_addm_low(t1, t0, a[1][2]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[1][2], t0, t1);

		fp2_norh_low(u3, u1);
		fp2_addc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[1][1]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[1][1], t1, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
	}
}

static void fp12_sqr_cyc_t(fp12_t c, fp12_t a) {
	fp2_t t0, t1, t2;
	dv2_t u0, u1, u2, u3;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	dv2_null(u0);
	dv2_null(u1);
	dv2_null(u2);
	dv2_null(u3);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);

		fp2_sqrn_low(u2, a[0][0]);
		fp2_sqrn_low(u3, a[0][1]);
		fp2_addm_low(t1, a[0][0], a[0][1]);

		fp2_norh_low(u0, u3);
		fp2_addc_low(u0, u0, u2);
		fp2_rdcn_low(t0, u0);

		fp2_sqrn_low(u1, t1);
		fp2_addc_low(u2, u2, u3);
		fp2_subc_low(u1, u1, u2);
		fp2_rdcn_low(t1, u1);

		fp2_subm_low(c[0][0], t0, a[0][0]);
		fp2_addm_low(c[0][0], c[0][0], c[0][0]);
		fp2_addm_low(c[0][0], t0, c[0][0]);

		fp2_addm_low(c[0][1], t1, a[0][1]);
		fp2_addm_low(c[0][1], c[0][1], c[0][1]);
		fp2_addm_low(c[0][1], t1, c[0][1]);

		fp2_sqrn_low(u0, a[1][1]);
		fp2_sqrn_low(u1, a[1][2]);
		fp2_addm_low(t0, a[1][1], a[1][2]);
		fp2_sqrn_low(u2, t0);

		fp2_addc_low(u3, u0, u1);
		fp2_subc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);

		fp2_addm_low(t1, a[0][2], a[1][0]);
		fp2_sqrm_low(t2, t1);
		fp2_sqrn_low(u2, a[0][2]);

		fp2_norm_low(t1, t0);
		fp2_addm_low(t0, t1, a[0][2]);
		fp2_addm_low(t0, t0, t0);
		fp2_addm_low(c[0][2], t0, t1);

		fp2_norh_low(u3, u1);
		fp2_addc_low(u3, u0, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[1][0]);

		fp2_sqrn_low(u1, a[1][0]);

		fp2_addm_low(t1, t1, t1);
		fp2_addm_low(c[1][0], t1, t0);

		fp2_norh_low(u3, u1);
		fp2_addc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[1][1]);
		fp2_addm_low(t1, t1, t1);
		fp2_addm_low(c[1][1], t1, t0);

		fp2_addc_low(u0, u2, u1);
		fp2_rdcn_low(t0, u0);
		fp2_subm_low(t0, t2, t0);
		fp2_addm_low(t1, t0, a[1][2]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[1][2], t0, t1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
	}
}

void fp12_back_cyc_sim_t(fp12_t c[], fp12_t a[], int n) {
    fp2_t *t = RLC_ALLOCA(fp2_t, n * 3);
    fp2_t
        *t0 = t + 0 * n,
        *t1 = t + 1 * n,
        *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp2_null(t0[i]);
			fp2_null(t1[i]);
			fp2_null(t2[i]);
			fp2_new(t0[i]);
			fp2_new(t1[i]);
			fp2_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			/* t0 = g4^2. */
			fp2_sqr(t0[i], a[i][1][1]);
			/* t1 = 3 * g4^2 - 2 * g3. */
			fp2_sub(t1[i], t0[i], a[i][1][0]);
			fp2_dbl(t1[i], t1[i]);
			fp2_add(t1[i], t1[i], t0[i]);
			/* t0 = E * g5^2 + t1. */
			fp2_sqr(t2[i], a[i][1][2]);
			fp2_mul_nor(t0[i], t2[i]);
			fp2_add(t0[i], t0[i], t1[i]);
			/* t1 = (4 * g2). */
			fp2_dbl(t1[i], a[i][0][2]);
			fp2_dbl(t1[i], t1[i]);
		}

		/* t1 = 1 / t1. */
		fp2_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp2_mul(c[i][0][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp2_mul(t1[i], a[i][1][0], a[i][1][1]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp2_sqr(t2[i], c[i][0][1]);
			fp2_sub(t2[i], t2[i], t1[i]);
			fp2_dbl(t2[i], t2[i]);
			fp2_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp2_mul(t1[i], a[i][0][2], a[i][1][2]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp2_add(t2[i], t2[i], t1[i]);
			fp2_mul_nor(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0], c[i][0][0][0], 1);

			fp2_copy(c[i][1][1], a[i][1][1]);
			fp2_copy(c[i][0][2], a[i][0][2]);
			fp2_copy(c[i][1][0], a[i][1][0]);
			fp2_copy(c[i][1][2], a[i][1][2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp2_free(t0[i]);
			fp2_free(t1[i]);
			fp2_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

static void fp12_pow(fp12_t r, const fp12_t a, const sm9_bn_t k)
{
	char kbits[257];
	fp12_t t;
	int lowest_bit_index;
	int i;

	fp12_null(t);
	fp12_new(t);

	// assert(sm9_bn_cmp(k, SM9_P_MINUS_ONE) < 0);
	fp12_set_dig(t, 0);
	
	lowest_bit_index = bn_to_bits(k, kbits);
	fp12_set_dig(t, 1);
	for (i = lowest_bit_index; i < 256; i++) {
	// for (i = 0; i < 256; i++) {
		fp12_sqr_t(t, t);
		// 测试fp12_sqr的性能影响
		// fp12_sqr(t,t);
		if (kbits[i] == '1') {
			fp12_mul_t(t, t, a);
			// 测试fp12_mul的性能影响
			// fp12_mul(t, t, a);
		}
	}
	fp12_copy(r, t);

	fp12_free(t);
}

static void fp12_pow_t(fp12_t c, fp12_t a, bn_t b) {
	fp12_t t;

	if (bn_is_zero(b)) {
		fp12_set_dig(c, 1);
		return;
	}

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		fp12_copy(t, a);

		for (int i = bn_bits(b) - 2; i >= 0; i--) {
			fp12_sqr_t(t, t);
			if (bn_get_bit(b, i)) {
				fp12_mul_t(t, t, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp12_inv_t(c, t);
		} else {
			fp12_copy(c, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t);
	}
}

//modify from fp12_exp_cyc_sps
void fp12_pow_cyc_sps_t(fp12_t c, fp12_t a, const int *b, int len, int sign) {
	int i, j, k, w = len;
    fp12_t t, *u = RLC_ALLOCA(fp12_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp12_set_dig(c, 1);
		return;
	}

	fp12_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp12_null(u[i]);
			fp12_new(u[i]);
		}
		fp12_new(t);

		fp12_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck_t(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc_t(u[i - 1], t);
				} else {
					fp12_copy(u[i - 1], t);
				}
			}

			fp12_back_cyc_sim_t(u, u, w - 1);

			fp12_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp12_mul_t(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck_t(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc_t(u[i], t);
				} else {
					fp12_copy(u[i], t);
				}
			}

			fp12_back_cyc_sim_t(u, u, w);

			fp12_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp12_mul_t(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp12_inv_cyc_t(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp12_free(u[i]);
		}
		fp12_free(t);
		RLC_FREE(u);
	}
}

void fp12_frb_t(fp12_t c, fp12_t a, int i) {

	fp12_copy(c, a);
	for (; i % 12 > 0; i--) {
		fp2_frb(c[0][0], c[0][0], 1);
		fp2_frb(c[1][1], c[1][1], 1);
		fp2_frb(c[1][0], c[1][0], 1);
		fp2_mul_frb(c[1][1], c[1][1], 1, 2);
		fp2_mul_frb(c[1][0], c[1][0], 1, 4);

		fp2_frb(c[0][2], c[0][2], 1);
		fp2_frb(c[0][1], c[0][1], 1);
		fp2_frb(c[1][2], c[1][2], 1);
		fp2_mul_frb(c[0][2], c[0][2], 1, 1);
		fp2_mul_frb(c[0][1], c[0][1], 1, 3);
		fp2_mul_frb(c[1][2], c[1][2], 1, 5);
	}
}

static void fp12_frobenius(fp12_t r, const fp12_t x)
{

	const fp2_t *xa = x[0][0];
	const fp2_t *xb = x[0][2];
	const fp2_t *xc = x[1][1];
	fp4_t ra;
	fp4_t rb;
	fp4_t rc;

	fp4_null(ra);
	fp4_null(rb);
	fp4_null(rc);

	fp4_new(ra);
	fp4_new(rb);
	fp4_new(rc);

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul_fp(ra[1], ra[1], SM9_ALPHA3);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul_fp(rb[0], rb[0], SM9_ALPHA1);
	fp2_conjugate(rb[1], xb[1]);
	fp2_mul_fp(rb[1], rb[1], SM9_ALPHA4);

	fp2_conjugate(rc[0], xc[0]);
	fp2_mul_fp(rc[0], rc[0], SM9_ALPHA2);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul_fp(rc[1], rc[1], SM9_ALPHA5);

	fp12_set(r, ra, rb, rc);

	fp4_free(ra);
	fp4_free(rb);
	fp4_free(rc);
}

static void fp12_frobenius2(fp12_t r, const fp12_t x)
{
	fp4_t a;
	fp4_t b;
	fp4_t c;
	
	fp4_null(a);
	fp4_null(b);
	fp4_null(c);

	fp4_new(a);
	fp4_new(b);
	fp4_new(c);
	
	fp4_conjugate(a, x[0][0]);
	fp4_conjugate(b, x[0][2]);
	fp4_mul_fp(b, b, SM9_ALPHA2);
	fp4_conjugate(c, x[1][1]);
	fp4_mul_fp(c, c, SM9_ALPHA4);

	fp4_copy(r[0][0], a);
	fp4_copy(r[0][2], b);
	fp4_copy(r[1][1], c);

	fp4_free(a);
	fp4_free(b);
	fp4_free(c);
}

static void fp12_frobenius3(fp12_t r, const fp12_t x)
{
	const fp2_t *xa = x[0][0];
	const fp2_t *xb = x[0][2];
	const fp2_t *xc = x[1][1];
	fp4_t ra;
	fp4_t rb;
	fp4_t rc;

	fp4_null(ra);
	fp4_null(rb);
	fp4_null(rc);

	fp4_new(ra);
	fp4_new(rb);
	fp4_new(rc);

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul(ra[1], ra[1], SM9_BETA);
	fp2_neg(ra[1], ra[1]);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul(rb[0], rb[0], SM9_BETA);
	fp2_conjugate(rb[1], xb[1]);

	fp2_conjugate(rc[0], xc[0]);
	fp2_neg(rc[0], rc[0]);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul(rc[1], rc[1], SM9_BETA);

	fp4_copy(r[0][0], ra);
	fp4_copy(r[0][2], rb);
	fp4_copy(r[1][1], rc);

	fp4_free(ra);
	fp4_free(rb);
	fp4_free(rc);
}

static void fp12_frobenius6(fp12_t r, const fp12_t x)
{
	fp4_t a;
	fp4_t b;
	fp4_t c;

	fp4_null(a);
	fp4_null(b);
	fp4_null(c);

	fp4_new(a);
	fp4_new(b);
	fp4_new(c);

	fp4_copy(a, x[0][0]);
	fp4_copy(b, x[0][2]);
	fp4_copy(c, x[1][1]);

	fp4_conjugate(a, a);
	fp4_conjugate(b, b);
	fp4_neg(b, b);
	fp4_conjugate(c, c);

	fp4_copy(r[0][0], a);
	fp4_copy(r[0][2], b);
	fp4_copy(r[1][1], c);

	fp4_free(a);
	fp4_free(b);
	fp4_free(c);
}

void fp12_conv_cyc_t(fp12_t c, fp12_t a) {
	fp12_t t;

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		/* First, compute c = a^(p^6 - 1). */
		/* t = a^{-1}. */
		fp12_inv_t(t, a);
		/* c = a^(p^6). */
		fp12_inv_cyc_t(c, a);
		/* c = a^(p^6 - 1). */
		fp12_mul_t(c, c, t);

		/* Second, compute c^(p^2 + 1). */
		/* t = c^(p^2). */
		fp12_frb_t(t, c, 2);

		/* c = c^(p^2 + 1). */
		fp12_mul_t(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t);
	}
}

#include <inttypes.h>
static void ep2_pi1(ep2_t R, const ep2_t P)
{
 //const c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
 fp_t c = {0x1a98dfbd4575299f, 0x9ec8547b245c54fd, 0xf51f5eac13df846c, 0x9ef74015d5a16393};
 // fp_null(c);
 // fp_new(c);

 // char c_str[] = "3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B";

 // fp_read_str(c, c_str, strlen(c_str), 16);
 // printf("c[0] = %"PRIx64"\n", c[0]);
 // printf("c[1] = %"PRIx64"\n", c[1]);
 // printf("c[2] = %"PRIx64"\n", c[2]);
 // printf("c[3] = %"PRIx64"\n", c[3]);
 // return 1;

 fp2_conjugate(R->x, P->x);  // X[0], -X[1]
 fp2_conjugate(R->y, P->y);
 fp2_conjugate(R->z, P->z);
 fp2_mul_fp(R->z, R->z, c);

 fp_free(c);
}

static void ep2_pi2(ep2_t R, const ep2_t P)
{
 //c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
 fp_t c = {0xb626197dce4736ca, 0x8296b3557ed0186, 0x9c705db2fd91512a, 0x1c753e748601c992};
 // fp_null(c);
 // fp_new(c);

 // char c_str[] = "F300000002A3A6F2780272354F8B78F4D5FC11967BE65334";

 // fp_read_str(c, c_str, strlen(c_str), 16);
 // printf("c[0] = %"PRIx64"\n", c[0]);
 // printf("c[1] = %"PRIx64"\n", c[1]);
 // printf("c[2] = %"PRIx64"\n", c[2]);
 // printf("c[3] = %"PRIx64"\n", c[3]);
 // return 1;

 fp2_copy(R->x, P->x);
 fp2_neg(R->y, P->y);
 fp2_mul_fp(R->z, P->z, c);

 fp_free(c);
}
/* 即ep2_add */
void ep2_add_full(ep2_t R, ep2_t P, ep2_t Q)
{
	const fp_t *X1 = P->x;
	const fp_t *Y1 = P->y;
	const fp_t *Z1 = P->z;
	const fp_t *X2 = Q->x;
	const fp_t *Y2 = Q->y;
	const fp_t *Z2 = Q->z;
	fp2_t T1, T2, T3, T4, T5, T6, T7, T8;

	fp2_null(T1);
	fp2_null(T2);
	fp2_null(T3);
	fp2_null(T4);
	fp2_null(T5);
	fp2_null(T6);
	fp2_null(T7);
	fp2_null(T8);

	fp2_new(T1);
	fp2_new(T2);
	fp2_new(T3);
	fp2_new(T4);
	fp2_new(T5);
	fp2_new(T6);
	fp2_new(T7);
	fp2_new(T8);

	if (ep2_is_infty(Q)) {
		ep2_copy(R, P);
		return ;
	}
	if (ep2_is_infty(P)) {
		ep2_copy(R, Q);
		return ;
	}

	fp2_sqr(T1, Z1);
	fp2_sqr(T2, Z2);
	fp2_mul(T3, X2, T1);
	fp2_mul(T4, X1, T2);
	fp2_add(T5, T3, T4);
	fp2_sub(T3, T3, T4);
	fp2_mul(T1, T1, Z1);
	fp2_mul(T1, T1, Y2);
	fp2_mul(T2, T2, Z2);
	fp2_mul(T2, T2, Y1);
	fp2_add(T6, T1, T2);
	fp2_sub(T1, T1, T2);

	if (fp2_is_zero(T1) && fp2_is_zero(T3)) {
		return ep2_dbl_projc(R, P);
	}
	
	if (fp2_is_zero(T1) && fp2_is_zero(T6)) {
		return ep2_set_infty(R);
	}

	fp2_sqr(T6, T1);
	fp2_mul(T7, T3, Z1);
	fp2_mul(T7, T7, Z2);
	fp2_sqr(T8, T3);
	fp2_mul(T5, T5, T8);
	fp2_mul(T3, T3, T8);
	fp2_mul(T4, T4, T8);
	fp2_sub(T6, T6, T5);
	fp2_sub(T4, T4, T6);
	fp2_mul(T1, T1, T4);
	fp2_mul(T2, T2, T3);
	fp2_sub(T1, T1, T2);

	fp2_copy(R->x, T6);
	fp2_copy(R->y, T1);
	fp2_copy(R->z, T7);

	fp2_free(T1);
	fp2_free(T2);
	fp2_free(T3);
	fp2_free(T4);
	fp2_free(T5);
	fp2_free(T6);
	fp2_free(T7);
	fp2_free(T8);
}

/* 特殊加法 当Q.Z =1时适用 */
void ep2_add_t(ep2_t R, ep2_t P, ep2_t Q){
	
	const fp_t *X1 = P->x;
	const fp_t *Y1 = P->y;
	const fp_t *Z1 = P->z;
	const fp_t *X2 = Q->x;
	const fp_t *Y2 = Q->y;
	fp2_t T1, T2, T3, T4, X3,Y3,Z3;

	fp2_null(T1);
	fp2_null(T2);
	fp2_null(T3);
	fp2_null(T4);
	fp2_null(X3);
	fp2_null(Y3);
	fp2_null(Z3);

	fp2_new(T1);
	fp2_new(T2);
	fp2_new(T3);
	fp2_new(T4);
	fp2_new(X3);
	fp2_new(Y3);
	fp2_new(Z3);

	if (ep2_is_infty(Q)) {
		ep2_copy(R, P);
		return ;
	}
	if (ep2_is_infty(P)) {
		ep2_copy(R, Q);
		return ;
	}

	fp2_sqr(T1, Z1);
	fp2_mul(T2, T1, Z1);
	fp2_mul(T1, T1, X2);
	fp2_mul(T2, T2, Y2);
	fp2_sub(T1, T1, X1);
	fp2_sub(T2, T2, Y1);

	if (fp2_is_zero(T1)) {
		if(fp2_is_zero(T2)){
			ep2_dbl_projc(R, Q);
			return ;
		}
		else{
			ep2_set_infty(R);
			return ;
		}
	}

	fp2_mul(Z3, Z1, T1);
	fp2_sqr(T3, T1);
	fp2_mul(T4, T3, T1);
	fp2_mul(T3, T3, X1);
	fp2_dbl(T1, T3);
	fp2_sqr(X3, T2);
	fp2_sub(X3, X3, T1);
	fp2_sub(X3, X3, T4);
	fp2_sub(T3, T3, X3);
	fp2_mul(T3, T3, T2);
	fp2_mul(T4, T4, Y1);
	fp2_sub(Y3, T3, T4);

	fp2_copy(R->x, X3);
	fp2_copy(R->y, Y3);
	fp2_copy(R->z, Z3);

	fp2_free(T1);
	fp2_free(T2);
	fp2_free(T3);
	fp2_free(T4);
	fp2_free(X3);
	fp2_free(Y3);
	fp2_free(Z3);
}

static void sm9_eval_g_line(fp12_t num, fp12_t den, ep2_t T, ep2_t P, ep_t Q){
	const fp_t *XP = P->x;
	const fp_t *YP = P->y;
	const fp_t *ZP = P->z;
	const fp_t *XT = T->x;
	const fp_t *YT = T->y;
	const fp_t *ZT = T->z;
	const uint64_t *xQ = Q->x;
	const uint64_t *yQ = Q->y;

	fp_t *a0 = num[0][0];
	fp_t *a1 = num[0][1];
	fp_t *a4 = num[1][1];
	fp_t *b1 = den[0][1];

	fp2_t T0, T1, T2, T3, T4;
	fp2_t two_inv;
	bn_t three;

	fp2_null(T0);
	fp2_null(T1);
	fp2_null(T2);
	fp2_null(T3);
	fp2_null(T4);

	fp2_null(two_inv);
	bn_null(three);

	fp2_new(T0);
	fp2_new(T1);
	fp2_new(T2);
	fp2_new(T3);
	fp2_new(T4);
	fp2_new(two_inv);
	bn_new(three);

	fp12_set_dig(num, 0);
	fp12_set_dig(den, 0);
	fp2_set_dig(two_inv, 2);
	fp2_inv(two_inv, two_inv);
	bn_set_dig(three, 3);

	fp2_sqr(T0, ZP);
	fp2_mul(T1, T0, XT);
	fp2_mul(T0, T0, ZP);
	fp2_sqr(T2, ZT);
	fp2_mul(T3, T2, XP);
	fp2_mul(T2, T2, ZT);
	fp2_mul(T2, T2, YP);
	fp2_sub(T1, T1, T3);
	fp2_mul(T1, T1, ZT);
	fp2_mul(T1, T1, ZP);
	fp2_mul(T4, T1, T0);
	fp2_copy(b1, T4);

	fp2_mul(T1, T1, YP);
	fp2_mul(T3, T0, YT);
	fp2_sub(T3, T3, T2);
	fp2_mul(T0, T0, T3);
	fp2_mul_fp(T0, T0, xQ);
	fp2_copy(a4, T0);

	fp2_mul(T3, T3, XP);
	fp2_mul(T3, T3, ZP);
	fp2_sub(T1, T1, T3);
	fp2_copy(a0, T1);

	fp2_mul_fp(T2, T4, yQ);
	fp2_neg(T2, T2);
	fp2_copy(a1, T2);

	fp2_free(T0);
	fp2_free(T1);
	fp2_free(T2);
	fp2_free(T3);
	fp2_free(T4);
	fp2_free(two_inv);
	bn_free(three);
}

static void sm9_eval_g_line_no_den(fp12_t num, fp12_t den, ep2_t T, ep2_t P, ep_t Q){
	const fp_t *XP = P->x;
	const fp_t *YP = P->y;
	const fp_t *ZP = P->z;
	const fp_t *XT = T->x;
	const fp_t *YT = T->y;
	const fp_t *ZT = T->z;
	const uint64_t *xQ = Q->x;
	const uint64_t *yQ = Q->y;

	fp_t *a0 = num[0][0];
	fp_t *a1 = num[0][1];
	fp_t *a4 = num[1][1];
	// fp_t *b1 = den[0][1];

	fp2_t T0, T1, T2, T3, T4;
	fp2_t two_inv;
	bn_t three;

	fp2_null(T0);
	fp2_null(T1);
	fp2_null(T2);
	fp2_null(T3);
	fp2_null(T4);

	fp2_null(two_inv);
	bn_null(three);

	fp2_new(T0);
	fp2_new(T1);
	fp2_new(T2);
	fp2_new(T3);
	fp2_new(T4);
	fp2_new(two_inv);
	bn_new(three);

	fp12_set_dig(num, 0);
	fp12_set_dig(den, 0);
	fp2_set_dig(two_inv, 2);
	fp2_inv(two_inv, two_inv);
	bn_set_dig(three, 3);

	fp2_sqr(T0, ZP);
	fp2_mul(T1, T0, XT);
	fp2_mul(T0, T0, ZP);
	fp2_sqr(T2, ZT);
	fp2_mul(T3, T2, XP);
	fp2_mul(T2, T2, ZT);
	fp2_mul(T2, T2, YP);
	fp2_sub(T1, T1, T3);
	fp2_mul(T1, T1, ZT);
	fp2_mul(T1, T1, ZP);
	fp2_mul(T4, T1, T0);
	// fp2_copy(b1, T4);

	fp2_mul(T1, T1, YP);
	fp2_mul(T3, T0, YT);
	fp2_sub(T3, T3, T2);
	fp2_mul(T0, T0, T3);
	fp2_mul_fp(T0, T0, xQ);
	fp2_copy(a4, T0);

	fp2_mul(T3, T3, XP);
	fp2_mul(T3, T3, ZP);
	fp2_sub(T1, T1, T3);
	fp2_copy(a0, T1);

	fp2_mul_fp(T2, T4, yQ);
	fp2_neg(T2, T2);
	fp2_copy(a1, T2);

	fp2_free(T0);
	fp2_free(T1);
	fp2_free(T2);
	fp2_free(T3);
	fp2_free(T4);
	fp2_free(two_inv);
	bn_free(three);
}

void sm9_eval_g_tangent(fp12_t num, fp12_t den, ep2_t P, ep_t Q){
	// fp_t *x, *y;
	// x = Q->x;
	// y = Q->y;
	const fp_t *XP = P->x;
	const fp_t *YP = P->y;
	const fp_t *ZP = P->z;
	const uint64_t *xQ = Q->x;
	const uint64_t *yQ = Q->y;

	fp_t *a0 = num[0][0];
	fp_t *a1 = num[0][1];
	fp_t *a4 = num[1][1];
	fp_t *b1 = den[0][1];

	fp2_t t0;
	fp2_t t1;
	fp2_t t2;
	fp2_t two_inv;
	bn_t three;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	fp2_null(two_inv);
	bn_null(three);

	fp2_new(t0);
	fp2_new(t1);
	fp2_new(t2);
	fp2_new(two_inv);
	bn_new(three);

	fp12_set_dig(num, 0);
	fp12_set_dig(den, 0);
	fp2_set_dig(two_inv, 2);
	fp2_inv(two_inv, two_inv);
	bn_set_dig(three, 3);
	
	fp2_sqr(t0, ZP);
	fp2_mul(t1, t0, ZP);
	fp2_mul(b1, t1, YP);
	fp2_mul_fp(t2, b1, yQ);
	fp2_neg(a1, t2);
	fp2_sqr(t1, XP);
	fp2_mul(t0, t0, t1);
	fp2_mul_fp(t0, t0, xQ);
	fp2_mul_dig(t0, t0, 3);
	fp2_mul(a4, t0, two_inv);
	fp2_mul(t1, t1, XP);
	fp2_mul_dig(t1, t1, 3);
	fp2_mul(t1, t1, two_inv);
	fp2_sqr(t0, YP);
	fp2_sub(a0, t0, t1);

	fp2_free(t0);
	fp2_free(t1);
	fp2_free(t2);
	fp2_free(two_inv);
	bn_free(three);
}

static void sm9_final_exponent_hard_part(fp12_t r, const fp12_t f)
{
	// a2 = 0xd8000000019062ed0000b98b0cb27659
	// a3 = 0x2400000000215d941
	const sm9_bn_t a2 = {0xcb27659, 0x0000b98b, 0x019062ed, 0xd8000000, 0, 0, 0, 0};
	const sm9_bn_t a3 = {0x215d941, 0x40000000, 0x2, 0, 0, 0, 0, 0};
	const sm9_bn_t nine = {9,0,0,0,0,0,0,0};

	fp12_t t0, t1, t2, t3;

	fp12_null(t0);
	fp12_null(t1);
	fp12_null(t2);
	fp12_null(t3);

	fp12_new(t0);
	fp12_new(t1);
	fp12_new(t2);
	fp12_new(t3);


	fp12_pow(t0, f, a3);

	fp12_inv_t(t0, t0);
	// PERFORMANCE_TEST("fp12_inv_t(t0, t0)",fp12_inv_t(t0, t0),1000);
	fp12_frobenius(t1, t0);
	//PERFORMANCE_TEST_NEW("fp12_frobenius(t1, t0)",fp12_frobenius(t1, t0));
	fp12_mul_t(t1, t0, t1);

	fp12_mul_t(t0, t0, t1);
	fp12_frobenius(t2, f);
	//PERFORMANCE_TEST_NEW("fp12_frobenius(t2, f)",fp12_frobenius2(t2, f));
	fp12_mul_t(t3, t2, f);
	fp12_pow(t3, t3, nine);


	fp12_mul_t(t0, t0, t3);
	fp12_sqr_t(t3, f);
	fp12_sqr_t(t3, t3);
	fp12_mul_t(t0, t0, t3);
	fp12_sqr_t(t2, t2);
	fp12_mul_t(t2, t2, t1);
	fp12_frobenius2(t1, f);
	//PERFORMANCE_TEST_NEW("fp12_frobenius2(t1, f)",fp12_frobenius2(t1, f));
	fp12_mul_t(t1, t1, t2);

	fp12_pow(t2, t1, a2);
	// fp12_pow正确性测试
	// printf("fp12_pow(t2, t1, a2)\n");
	// fp12_print(t2);
	// fp12_pow性能测试
	// PERFORMANCE_TEST_NEW("fp12_pow(t2, t1, a2)",fp12_pow(t2, t1, a2));
#if 0
	char a2_str[] = "11011000000000000000000000000000000000011001000001100010111011010000000000000000101110011000101100001100101100100111011001011001";
	uint64_t a2_t[] = {0x0000b98bcb27659, 0xd8000000019062ed};
	bn_t tmp;
	bn_null(tmp);
	bn_new(tmp);
	bn_read_str(tmp, a2_str, 128, 2);

	bn_print(tmp);

	fp12_exp(r,t1,tmp);
	// printf("fp12_exp\n");
	// fp12_print(r);

	fp12_exp_dig(r,t1,a2_t);
	// printf("fp12_exp_dig\n");
	// fp12_print(r);

	// PERFORMANCE_TEST_NEW("fp12_exp(r,r,tmp)",fp12_exp(r,r,tmp));
	// PERFORMANCE_TEST_NEW("fp12_exp_dig(r,t1,a2_t)",fp12_exp_dig(r,t1,a2));

	bn_free(tmp);
#endif
	fp12_mul_t(t0, t2, t0);
	fp12_frobenius3(t1, f);
	
	//PERFORMANCE_TEST_NEW("\nfp12_frobenius3\n",fp12_frobenius3(t1, f));

	fp12_mul_t(t1, t1, t0);

	fp12_copy(r, t1);

	fp12_free(t0);
	fp12_free(t1);
	fp12_free(t2);
	fp12_free(t3);
}

static void sm9_final_exponent_hard_parter(fp12_t r, const fp12_t f)
{

	const sm9_bn_t a2 = {0xcb27659, 0x0000b98b, 0x019062ed, 0xd8000000, 0, 0, 0, 0};
	const sm9_bn_t a3 = {0x215d941, 0x40000000, 0x2, 0, 0, 0, 0, 0};
	const sm9_bn_t nine = {9,0,0,0,0,0,0,0};

	const bn_t a3_t;
	const bn_t a2_t;
	const bn_t nine_t;

	bn_null(a3_t);
	bn_null(a2_t);
	bn_null(nine_t);
	bn_new(a3_t);
	bn_new(a2_t);
	bn_new(nine_t);

	bn_to_bn(a3_t,a3);
	bn_to_bn(a2_t,a2);
	bn_to_bn(nine_t,nine);


	fp12_t t0, t1, t2, t3;

	fp12_null(t0);
	fp12_null(t1);
	fp12_null(t2);
	fp12_null(t3);

	fp12_new(t0);
	fp12_new(t1);
	fp12_new(t2);
	fp12_new(t3);

	fp12_pow_t(t0, f, a3_t);

	//PERFORMANCE_TEST_NEW("fp12_pow_t(t0, f, a3_t)",fp12_pow_t(t0, f, a3_t));

	fp12_inv_t(t0, t0);

	fp12_frb_t(t1,t0,1);
	//fp12_frobenius(t1, t0);
	
	fp12_mul_t(t1, t0, t1);

	fp12_mul_t(t0, t0, t1);
	
	fp12_frb_t(t2,f,1);
	//fp12_frobenius(t2, f);
	
	fp12_mul_t(t3, t2, f);
	fp12_pow_t(t3, t3, nine_t);


	fp12_mul_t(t0, t0, t3);
	fp12_sqr_t(t3, f);
	fp12_sqr_t(t3, t3);
	fp12_mul_t(t0, t0, t3);
	fp12_sqr_t(t2, t2);
	fp12_mul_t(t2, t2, t1);
	
	fp12_frb_t(t1,f,2);
	//PERFORMANCE_TEST_NEW("fp12_frb_t(t1, f,2)",fp12_frb_t(t1, f,2));
	//fp12_frobenius2(t1, f);

	fp12_mul_t(t1, t1, t2);

	fp12_pow_t(t2, t1, a2_t);


	bn_free(tmp);

	fp12_mul_t(t0, t2, t0);
	fp12_frb_t(t1,f,3);
	//PERFORMANCE_TEST_NEW("fp12_frb_t(t1, f,3)",fp12_frb_t(t1, f,3));
	//fp12_frobenius3(t1,f);

	fp12_mul_t(t1, t1, t0);

	fp12_copy(r, t1);

	fp12_free(t0);
	fp12_free(t1);
	fp12_free(t2);
	fp12_free(t3);
}

static void sm9_final_exponent_hard_part_t(fp12_t r, const fp12_t f)
{
	// a2 = 0xd8000000019062ed0000b98b0cb27659
	// a3 = 0x2400000000215d941
	const sm9_bn_t a2 = {0xcb27659, 0x0000b98b, 0x019062ed, 0xd8000000, 0, 0, 0, 0};
	const sm9_bn_t a3 = {0x215d941, 0x40000000, 0x2, 0, 0, 0, 0, 0};
	const sm9_bn_t nine = {9,0,0,0,0,0,0,0};

	const bn_t a3_t;
	const bn_t a2_t;
	const bn_t nine_t;

	bn_null(a3_t);
	bn_null(a2_t);
	bn_null(nine_t);
	bn_new(a3_t);
	bn_new(a2_t);
	bn_new(nine_t);

	bn_to_bn(a3_t,a3);
	bn_to_bn(a2_t,a2);
	bn_to_bn(nine_t,nine);


	fp12_t t0, t1, t2, t3;

	fp12_null(t0);
	fp12_null(t1);
	fp12_null(t2);
	fp12_null(t3);

	fp12_new(t0);
	fp12_new(t1);
	fp12_new(t2);
	fp12_new(t3);

	fp12_pow_t(t0, f, a3_t);

	//PERFORMANCE_TEST_NEW("fp12_pow_t(t0, f, a3_t)",fp12_pow_t(t0, f, a3_t));

	fp12_inv_t(t0, t0);

	//fp12_frb_t(t1,t0,1);
	fp12_frobenius(t1, t0);
	
	fp12_mul_t(t1, t0, t1);

	fp12_mul_t(t0, t0, t1);
	
	//fp12_frb_t(t2,f,1);
	fp12_frobenius(t2, f);
	
	fp12_mul_t(t3, t2, f);
	fp12_pow_t(t3, t3, nine_t);


	fp12_mul_t(t0, t0, t3);
	fp12_sqr_t(t3, f);
	fp12_sqr_t(t3, t3);
	fp12_mul_t(t0, t0, t3);
	fp12_sqr_t(t2, t2);
	fp12_mul_t(t2, t2, t1);
	
	//fp12_frb_t(t1,f,2);
	//PERFORMANCE_TEST_NEW("fp12_frb_t(t1, f,2)",fp12_frb_t(t1, f,2));
	fp12_frobenius2(t1, f);

	fp12_mul_t(t1, t1, t2);

	fp12_pow_t(t2, t1, a2_t);
	// fp12_pow正确性测试
	// printf("fp12_pow(t2, t1, a2)\n");
	// fp12_print(t2);
	// fp12_pow性能测试
	// PERFORMANCE_TEST_NEW("fp12_pow(t2, t1, a2)",fp12_pow(t2, t1, a2));
#if 0
	char a2_str[] = "11011000000000000000000000000000000000011001000001100010111011010000000000000000101110011000101100001100101100100111011001011001";
	uint64_t a2_t[] = {0x0000b98bcb27659, 0xd8000000019062ed};
	bn_t tmp;
	bn_null(tmp);
	bn_new(tmp);
	bn_read_str(tmp, a2_str, 128, 2);

	bn_print(tmp);

	fp12_exp(r,t1,tmp);
	// printf("fp12_exp\n");
	// fp12_print(r);

	fp12_exp_dig(r,t1,a2_t);
	// printf("fp12_exp_dig\n");
	// fp12_print(r);

	// PERFORMANCE_TEST_NEW("fp12_exp(r,r,tmp)",fp12_exp(r,r,tmp));
	// PERFORMANCE_TEST_NEW("fp12_exp_dig(r,t1,a2_t)",fp12_exp_dig(r,t1,a2));

	bn_free(tmp);
#endif
	fp12_mul_t(t0, t2, t0);
	//fp12_frb_t(t1,f,3);
	//PERFORMANCE_TEST_NEW("fp12_frb_t(t1, f,3)",fp12_frb_t(t1, f,3));
	fp12_frobenius3(t1,f);

	fp12_mul_t(t1, t1, t0);

	fp12_copy(r, t1);

	fp12_free(t0);
	fp12_free(t1);
	fp12_free(t2);
	fp12_free(t3);
}

static void pp_pow_bn_t(fp12_t c, fp12_t a) {
	fp12_t y0, y1, y2, y3,T0;
	bn_t x;
	const int *b;
	int l;

	fp12_null(y0);
	fp12_null(y1);
	fp12_null(y2);
	fp12_null(y3);
	fp12_null(T0);
	bn_null(x);

	RLC_TRY {
		fp12_new(y0);
		fp12_new(y1);
		fp12_new(y2);
		fp12_new(y3);
		fp12_new(T0);
		bn_new(x);

		fp_prime_get_par(x);                
		b = fp_prime_get_par_sps(&l);       

		fp12_conv_cyc_t(c, a);

		fp12_inv_cyc_t(y0,c);
		fp12_pow_cyc_sps_t(T0, y0, b, l, RLC_POS);   
		fp12_sqr_cyc_t(y3,T0);
		PERFORMANCE_TEST_NEW("RELIC 分圆子群", fp12_sqr_cyc_t(y3,T0));
		fp12_frb_t(y2,y3,1);                         
		fp12_mul_t(y2,y3,y2);
		fp12_sqr_cyc_t(y2,y2);
		fp12_mul_t(y2,y3,y2);

		fp12_mul_t(y1,y3,T0);
		fp12_pow_cyc_sps_t(T0, y1, b, l, RLC_NEG);
		fp12_frb_t(y1,T0,2);
		fp12_mul_t(y1,y0,y1);
		fp12_inv_cyc_t(T0,T0);
		fp12_frb_t(y3,T0,1);
		PERFORMANCE_TEST_NEW("RELIC fro", fp12_frb_t(y3,T0,1));
		fp12_mul_t(y3,T0,y3);
		fp12_sqr_cyc_t(T0,T0);
		fp12_mul_t(y1,T0,y1);
		
		fp12_pow_cyc_sps_t(T0, y3, b, l, RLC_NEG);
		fp12_sqr_cyc_t(T0,T0);
		fp12_inv_cyc_t(T0,T0);
		fp12_mul_t(y3,T0,y3);
		
		fp12_frb_t(T0,c,1);
		fp12_frb_t(y0,c,2);
		fp12_mul_t(y0,T0,y0);
		fp12_frb_t(T0,c,3);
		fp12_mul_t(y0,T0,y0);

		fp12_sqr_cyc_t(T0,y3);
		fp12_mul_t(T0,T0,y2);
		fp12_mul_t(y3,T0,y0);
		fp12_mul_t(T0,T0,y1);
		fp12_sqr_cyc_t(T0,T0);
		fp12_mul_t(c,T0,y3);


	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(y0);
		fp12_free(y1);
		fp12_free(y2);
		fp12_free(y3);
		fp12_free(T0);
		bn_free(x);
	}
}

static void sm9_final_exponent(fp12_t r, const fp12_t f)
{
	fp12_t t0;
	fp12_t t1;

	fp12_null(t0);
	fp12_null(t1);

	fp12_new(t0);
	fp12_new(t1);

	fp12_frobenius6(t0, f);
	
	//PERFORMANCE_TEST_NEW("\nfp12_frobenius6\n",fp12_frobenius6(t0, f));

	fp12_inv_t(t1, f);

	fp12_mul_t(t0, t0, t1);

	fp12_frobenius2(t1, t0);

	//PERFORMANCE_TEST_NEW("fp12_frobenius2",fp12_frobenius2(t1, t0));
	fp12_mul_t(t0, t0, t1);

	sm9_final_exponent_hard_part(t0, t0);
	// PERFORMANCE_TEST_NEW("sm9_final_exponent_hard_part",sm9_final_exponent_hard_part(t0, t0));
	fp12_copy(r, t0);
	
	fp12_free(t0);
	fp12_free(t1);
}

static void sm9_final_exponent_t(fp12_t r, const fp12_t f)
{
	fp12_t t0;
	fp12_t t1;

	fp12_null(t0);
	fp12_null(t1);

	fp12_new(t0);
	fp12_new(t1);

	fp12_frb_t(t0, f,6);
	//fp12_frobenius6(t0,f);

	fp12_inv_t(t1, f);

	fp12_mul_t(t0, t0, t1);
	
	fp12_frb_t(t1, t0,2);
	//fp12_frobenius2(t1,t0);

	fp12_mul_t(t0, t0, t1);

	sm9_final_exponent_hard_parter(t0, t0);
	// PERFORMANCE_TEST_NEW("sm9_final_exponent_hard_part",sm9_final_exponent_hard_part(t0, t0));
	fp12_copy(r, t0);
	
	fp12_free(t0);
	fp12_free(t1);
}

#if 1 // crude final exponent

static void sm9_final_exponent_hard_part1(fp12_t r, const fp12_t f)
{
	// a2 = 0xd8000000019062ed0000b98b0cb27659
	// a3 = 0x2400000000215d941
	const sm9_bn_t a2 = {0xcb27659, 0x0000b98b, 0x019062ed, 0xd8000000, 0, 0, 0, 0};
	const sm9_bn_t a3 = {0x215d941, 0x40000000, 0x2, 0, 0, 0, 0, 0};
	const sm9_bn_t nine = {9,0,0,0,0,0,0,0};
	fp12_t t0, t1, t2, t3;

	fp12_null(t0);
	fp12_null(t1);
	fp12_null(t2);
	fp12_null(t3);

	fp12_new(t0);
	fp12_new(t1);
	fp12_new(t2);
	fp12_new(t3);

	fp12_pow(t0, f, a3);
	// PERFORMANCE_TEST("fp12_pow(t0, f, a3)",fp12_pow(t0, f, a3),1000);
	fp12_inv_t(t0, t0);
	// PERFORMANCE_TEST("fp12_inv_t(t0, t0)",fp12_inv_t(t0, t0),1000);
	fp12_frobenius(t1, t0);
	// PERFORMANCE_TEST("fp12_frobenius(t1, t0)",fp12_frobenius(t1, t0),1000);
	fp12_mul_t1(t1, t0, t1);

	fp12_mul_t1(t0, t0, t1);
	fp12_frobenius(t2, f);
	fp12_mul_t1(t3, t2, f);
	fp12_pow(t3, t3, nine);

	fp12_mul_t1(t0, t0, t3);
	fp12_sqr_t1(t3, f);
	fp12_sqr_t1(t3, t3);
	fp12_mul_t1(t0, t0, t3);
	fp12_sqr_t1(t2, t2);
	fp12_mul_t1(t2, t2, t1);
	fp12_frobenius2(t1, f);
	// PERFORMANCE_TEST("fp12_frobenius2(t1, f)",fp12_frobenius2(t1, f),1000);
	fp12_mul_t1(t1, t1, t2);

	fp12_pow(t2, t1, a2);
	// PERFORMANCE_TEST("fp12_pow(t2, t1, a2)",fp12_pow(t2, t1, a2),1000);
	fp12_mul_t1(t0, t2, t0);
	fp12_frobenius3(t1, f);
	fp12_mul_t1(t1, t1, t0);

	fp12_copy(r, t1);

	fp12_free(t0);
	fp12_free(t1);
	fp12_free(t2);
	fp12_free(t3);
}

static void sm9_final_exponent1(fp12_t r, const fp12_t f)
{
	fp12_t t0;
	fp12_t t1;

	fp12_null(t0);
	fp12_null(t1);

	fp12_new(t0);
	fp12_new(t1);

	fp12_frobenius6(t0, f);
	// PERFORMANCE_TEST("fp12_frobenius6",fp12_frobenius6(t0, f),1000);
	fp12_inv_t(t1, f);

	fp12_mul_t1(t0, t0, t1);

	fp12_frobenius2(t1, t0);
	// PERFORMANCE_TEST("fp12_frobenius2",fp12_frobenius2(t1, t0),1000);
	fp12_mul_t1(t0, t0, t1);

	sm9_final_exponent_hard_part1(t0, t0);
	// PERFORMANCE_TEST("sm9_final_exponent_hard_part",sm9_final_exponent_hard_part(t0, t0),1000);
	fp12_copy(r, t0);
	
	fp12_free(t0);
	fp12_free(t1);
}

#endif


static void sm9_twist_point_neg(ep2_t R,const ep2_t Q){
	fp2_copy(R->x, Q->x);
	fp2_neg(R->y, Q->y);
	fp2_copy(R->z, Q->z);
}


//original pairing 
void sm9_pairing(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010000101011101100100111110";
	// const char *abits = "1";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, ep2_tmp2;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(ep2_tmp2);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(ep2_tmp2);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t1(f_num, f_num);
		fp12_sqr_t1(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_t1(f_num, f_num, g_num);
		fp12_mul_t1(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1')
		{
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_t1(f_num, f_num, g_num);
			fp12_mul_t1(f_den, f_den, g_den);
			ep2_add_projc(T, T, Q);  // T = T + Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_t1(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_t1(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_t1(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_t1(f_den, f_den, g_den);
	// ep2_add_projc(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t1(r, f_num, f_den);  // r = f_num*f_den = f

	sm9_final_exponent1(r, r);  // r = f^{(q^12-1)/r'}
	// PERFORMANCE_TEST("sm9_final_exponent", sm9_final_exponent(r, r), 1000);

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(ep2_tmp2);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);

	return ;
}

void sm9_pairing_fast(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t(f_num, f_num);
		fp12_sqr_t(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_sparse(f_num, f_num, g_num);
		fp12_mul_sparse(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t(r, f_num, f_den);  // r = f_num*f_den = f

	//pp_pow_bn_t(r,r);
	sm9_final_exponent(r, r);  // r = f^{(q^12-1)/r'}
	// PERFORMANCE_TEST_NEW("sm9_final_exponent", sm9_final_exponent(r, r));

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}


void sm9_pairing_faster(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t(f_num, f_num);
		fp12_sqr_t(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_sparse(f_num, f_num, g_num);
		fp12_mul_sparse(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t(r, f_num, f_den);  // r = f_num*f_den = f

	sm9_final_exponent_t(r, r);  // r = f^{(q^12-1)/r'}
	// PERFORMANCE_TEST_NEW("sm9_final_exponent", sm9_final_exponent(r, r));

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}

/*input:ep2 ep
output:fp12
*/
void sm9_pairing_fastest(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t(f_num, f_num);
		// fp12_sqr_t(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		fp12_mul_sparse(f_num, f_num, g_num);
		// fp12_mul_sparse(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line_no_den(g_num, g_den, T, Q, P);
			fp12_mul_sparse(f_num, f_num, g_num);
			// fp12_mul_sparse2(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_sparse(f_num, f_num, g_num);
			// fp12_mul_sparse2(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	PERFORMANCE_TEST_NEW("RELIC 直线", sm9_eval_g_tangent(g_num, g_den, T, P));
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	// fp12_mul_sparse2(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	// fp12_mul_sparse2(f_den, f_den, g_den);
	//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	// fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	// fp12_mul_t(r, f_num, f_den);  // r = f_num*f_den = f
	fp12_copy(r, f_num);
	pp_pow_bn_t(r,r); // r = f^{(q^12-1)/r'}
	//PERFORMANCE_TEST_NEW("RELIC final exp", pp_pow_bn_t(r,r));
	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}



void sm9_pairing_fastest2(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t(f_num, f_num);
		fp12_sqr_t(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_t(f_num, f_num, g_num);
		fp12_mul_sparse(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_t(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_t(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_t(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_t(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t(r, f_num, f_den);  // r = f_num*f_den = f

	pp_pow_bn_t(r,r); // r = f^{(q^12-1)/r'}
	// PERFORMANCE_TEST_NEW("sm9_final_exponent", sm9_final_exponent(r, r));

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}


void sm9_pairing_omp(fp12_t r_arr[], const ep2_t Q_arr[], const ep_t P_arr[], const size_t arr_size, const size_t threads_num){
	omp_set_num_threads(threads_num);	
	#pragma omp parallel	
	{
		int id = omp_get_thread_num();
		printf("id=%d\n", id);
		for (size_t i = 0; i < arr_size; i+=threads_num)
		{
			sm9_pairing(r_arr[(i+id)%arr_size], Q_arr[(i+id)%arr_size], P_arr[(i+id)%arr_size]);
		}
	}
}

void sm9_pairing_function_test(fp12_t r, const ep2_t Q, const ep_t P)
{
	// a)
	const char *abits = "00100000000000000000000000000000000000010000101011101100100111110";
	// const char *abits = "1";

	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, ep2_tmp2;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(ep2_tmp2);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(ep2_tmp2);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	PERFORMANCE_TEST_NEW("SM9 square ", fp12_sqr_t1(f_num, f_den));
	PERFORMANCE_TEST_NEW("SM9 square improved", fp12_sqr_t(f_num, f_den));
	// fp12_mul_t(f_num, f_num, g_num);
	PERFORMANCE_TEST_NEW("SM9 multiplication ",fp12_mul_t1(f_num, f_num, g_num) );

	
	// fp12_mul_t(f_num, f_num, g_num);
	PERFORMANCE_TEST_NEW("SM9 multiplication improved",fp12_mul_t(f_num, f_num, g_num) );
	PERFORMANCE_TEST_NEW("SM9 inverse ",fp12_inv_t(f_den, f_den) );


	
	PERFORMANCE_TEST_NEW("frobenius map ",ep2_pi1(Q1, Q));

	PERFORMANCE_TEST_NEW("ep2_dbl_projc  ",ep2_dbl_projc(T, T) );
	PERFORMANCE_TEST_NEW("SM9 evaluation of g_line ",sm9_eval_g_line(g_num, g_den, T, Q, P) );
	PERFORMANCE_TEST_NEW("SM9 evaluation of g_tangent ",sm9_eval_g_tangent(g_num, g_den, T, P));
	PERFORMANCE_TEST_NEW("SM9 twisted points add full ",ep2_add_full(T, T, Q1));

	PERFORMANCE_TEST_NEW("SM9 final exponentiation ",sm9_final_exponent1(r, r));
	PERFORMANCE_TEST_NEW("SM9 final exponentiation improved",sm9_final_exponent(r, r));
	
	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(ep2_tmp2);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);

	return 0;
}

void sm9_pairing_fastest_function_test(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	printf("raw:\n");
	PERFORMANCE_TEST_NEW("SM9 square ", fp12_sqr_t1(f_num, f_den));
	PERFORMANCE_TEST_NEW("SM9 square improved", fp12_sqr_t(f_num, f_den));
	// fp12_mul_t(f_num, f_num, g_num);
	PERFORMANCE_TEST_NEW("SM9 multiplication ",fp12_mul_t1(r, f_num, f_den) );

	
	// fp12_mul_t(f_num, f_num, g_num);
	PERFORMANCE_TEST_NEW("SM9 multiplication improved",fp12_mul_t(r, f_num, f_den) );
	
	
	printf("updated:\n");



	//PERFORMANCE_TEST_NEW("SM9 square improved", fp12_sqr_t(f_num, f_den));
	PERFORMANCE_TEST_NEW("SM9 square improved", fp12_sqr_t(f_num, f_den));
	// fp12_mul_t(f_num, f_num, g_num);
	PERFORMANCE_TEST_NEW("SM9 fp12_mul_sparse improved",fp12_mul_sparse(r, f_num, f_den) );

	
	// fp12_mul_t(f_num, f_num, g_num);
	PERFORMANCE_TEST_NEW("SM9 fp12_mul_sparse2 improved",fp12_mul_sparse2(r, f_num, f_den) );
	PERFORMANCE_TEST_NEW("SM9 fp12_mul_t improved",fp12_mul_t(r, f_num, f_den) );
	PERFORMANCE_TEST_NEW("SM9 fp12_inv_t improved",fp12_inv_t(f_den, f_den) );

	
	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}

void sm9_TEST(fp12_t r, const ep2_t Q, const ep_t P){
	PERFORMANCE_TEST_NEW("SM9 RELIC Pairing ",sm9_pairing(r,Q,P));


}


void sm9_pairing_steps_test(fp12_t r, const ep2_t Q, const ep_t P)
{
	// a)
	const char *abits = "00100000000000000000000000000000000000010000101011101100100111110";
	// const char *abits = "1";

	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, ep2_tmp2;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(ep2_tmp2);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(ep2_tmp2);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	int  count = 0;
	int second = 3;
	double d=0.0;
	signal(SIGALRM,alarmed_t);
	alarm(second);
	run_t = 1;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);


	for (size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t1(f_num, f_num);
		fp12_sqr_t1(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST_NEW("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P));

		fp12_mul_t1(f_num, f_num, g_num);
		fp12_mul_t1(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1')
		{
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);

			fp12_mul_t1(f_num, f_num, g_num);
			fp12_mul_t1(f_den, f_den, g_den);

			ep2_add_full(T, T, Q); // T = T + Q
		}
	}
	// d)
	ep2_pi1(Q1, Q); // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q); // Q2 = pi_{q^2}(Q), Q2 = -Q2

	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P); // g = g_{T,Q1}(P)
	fp12_mul_t1(f_num, f_num, g_num);		 // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_t1(f_den, f_den, g_den);
	ep2_add_full(T, T, Q1); // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P); // g = g_{T,-Q2}(P)
	fp12_mul_t1(f_num, f_num, g_num);		 // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_t1(f_den, f_den, g_den);
	ep2_add_full(T, T, Q2); // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den); // f_den = f_den^{-1}

	fp12_mul_t1(r, f_num, f_den); // r = f_num*f_den = f



	}


	d=TIME_F(STOP);
	printf("SM9 RELIC Miller part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);

	alarm(second);
	run_t = 1;
	d=0.0;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
		sm9_final_exponent1(r, r); // r = f^{(q^12-1)/r'}
		// PERFORMANCE_TEST("sm9_final_exponent", sm9_final_exponent(r, r), 1000);
	}
	d = TIME_F(STOP);
	printf("SM9 RELIC Final Exp part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(ep2_tmp2);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);

	return 0;
}


void sm9_pairing_fastest_step_test(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

int  count = 0;
	int second = 3;
	double d=0.0;
	signal(SIGALRM,alarmed_t);
	alarm(second);
	run_t = 1;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		


	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t(f_num, f_num);
		fp12_sqr_t(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_sparse(f_num, f_num, g_num);
		fp12_mul_sparse2(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t(r, f_num, f_den);  // r = f_num*f_den = f
	}
	
	d=TIME_F(STOP);
	printf("SM9 RELIC improved Miller part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);

	alarm(second);
	run_t = 1;
	d=0.0;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
		pp_pow_bn_t(r,r); // r = f^{(q^12-1)/r'}
	// PERFORMANCE_TEST_NEW("sm9_final_exponent", sm9_final_exponent(r, r));

	}
	d = TIME_F(STOP);
	printf("SM9 RELIC improved Final Exp part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);


	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}


void sm9_pairing_fast_step_test(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	int  count = 0;
	int second = 3;
	double d=0.0;
	signal(SIGALRM,alarmed_t);
	alarm(second);
	run_t = 1;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
	sm9_twist_point_neg(neg_Q,Q);


	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t(f_num, f_num);
		fp12_sqr_t(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_sparse(f_num, f_num, g_num);
		fp12_mul_sparse(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_sparse(f_num, f_num, g_num);
			fp12_mul_sparse2(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_sparse(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_sparse2(f_den, f_den, g_den);
//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t(r, f_num, f_den);  // r = f_num*f_den = f
	}


	d=TIME_F(STOP);
	printf("SM9 fast RELIC Miller part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);

	alarm(second);
	run_t = 1;
	d=0.0;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
		sm9_final_exponent(r, r);  // r = f^{(q^12-1)/r'}
		// PERFORMANCE_TEST("sm9_final_exponent", sm9_final_exponent(r, r), 1000);
	}
	d = TIME_F(STOP);
	printf("SM9 fast RELIC Final Exp part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);

	// PERFORMANCE_TEST("sm9_final_exponent", sm9_final_exponent(r, r), 1000);

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}



void sm9_pairing_fast_step_test2(fp12_t r, const ep2_t Q, const ep_t P){
	// a)
	const char *abits = "00100000000000000000000000000000000000010001020200020200101000020";
	
	fp12_t f, g, f_num, f_den, g_num, g_den, fp12_tmp;
	ep2_t T, Q1, Q2, ep2_tmp, neg_Q;
	ep_t _p;
	bn_t n;

	// null
	ep_null(_p);
	bn_null(n);
	ep2_null(T);
	ep2_null(Q1);
	ep2_null(Q2);
	ep2_null(ep2_tmp);
	ep2_null(neg_Q);
	fp12_null(f);
	fp12_null(g);
	fp12_null(f_num);
	fp12_null(f_den);
	fp12_null(g_num);
	fp12_null(g_den);
	fp12_null(fp12_tmp);

	ep_new(_p);
	bn_new(n);
	ep2_new(T);
	ep2_new(Q1);
	ep2_new(Q2);
	ep2_new(ep2_tmp);
	ep2_new(neg_Q);
	fp12_new(f);
	fp12_new(g);
	fp12_new(f_num);
	fp12_new(f_den);
	fp12_new(g_num);
	fp12_new(g_den);
	fp12_new(fp12_tmp);

	int  count = 0;
	int second = 3;
	double d=0.0;
	signal(SIGALRM,alarmed_t);
	alarm(second);
	run_t = 1;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
	sm9_twist_point_neg(neg_Q,Q);

	// b)
	ep2_copy(T, Q);
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);

	for(size_t i = 0; i < strlen(abits); i++)
	{
		// c)
		fp12_sqr_t1(f_num, f_num);
		fp12_sqr_t1(f_den, f_den);

		sm9_eval_g_tangent(g_num, g_den, T, P);
		// PERFORMANCE_TEST("sm9_eval_g_tangent",sm9_eval_g_tangent(g_num, g_den, T, P),10000);

		fp12_mul_t1(f_num, f_num, g_num);
		fp12_mul_t1(f_den, f_den, g_den);

		ep2_dbl_projc(T, T);
		// c.2)
		if (abits[i] == '1'){
			sm9_eval_g_line(g_num, g_den, T, Q, P);
			// PERFORMANCE_TEST("sm9_eval_g_line",sm9_eval_g_line(g_num, g_den, T, Q, P),10000);
			fp12_mul_t1(f_num, f_num, g_num);
			fp12_mul_t1(f_den, f_den, g_den);

			ep2_add_projc(T, T, Q);  // T = T + Q
		}
		else if(abits[i] == '2'){
			sm9_eval_g_line(g_num, g_den, T, neg_Q, P);
			fp12_mul_t1(f_num, f_num, g_num);
			fp12_mul_t1(f_den, f_den, g_den);
			ep2_add_projc(T, T, neg_Q);  // T = T - Q
		}
	}
	// d)
	ep2_pi1(Q1, Q);  // Q1 = pi_q(Q)
	ep2_pi2(Q2, Q);  // Q2 = pi_{q^2}(Q), Q2 = -Q2
	
	// e)
	sm9_eval_g_line(g_num, g_den, T, Q1, P);  // g = g_{T,Q1}(P)
	fp12_mul_t1(f_num, f_num, g_num);  // f = f * g = f * g_{T,Q1}(P)
	fp12_mul_t1(f_den, f_den, g_den);
	ep2_add_projc(T, T, Q1);  // T = T + Q1

	// f)
	sm9_eval_g_line(g_num, g_den, T, Q2, P);  // g = g_{T,-Q2}(P)
	fp12_mul_t1(f_num, f_num, g_num);  // f = f * g = f * g_{T,-Q2}(P)
	fp12_mul_t1(f_den, f_den, g_den);
//	ep2_add(T, T, Q2);  // T = T - Q2

	// g)
	fp12_inv_t(f_den, f_den);  // f_den = f_den^{-1}

	fp12_mul_t1(r, f_num, f_den);  // r = f_num*f_den = f
	}


	d=TIME_F(STOP);
	printf("SM9 fast with slow loop RELIC Miller part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);

	alarm(second);
	run_t = 1;
	d=0.0;
	TIME_F(START);
	for(count=0;run_t&&count<0x7fffffff;count++){
		
		sm9_final_exponent(r, r);  // r = f^{(q^12-1)/r'}
		// PERFORMANCE_TEST("sm9_final_exponent", sm9_final_exponent(r, r), 1000);
	}
	d = TIME_F(STOP);
	printf("SM9 fast with slow loop RELIC Final Exp part \n\t\t\t run %d times in %.2fs \n",count/second,d/second);
	
	// PERFORMANCE_TEST("sm9_final_exponent", sm9_final_exponent(r, r), 1000);

	ep_free(_p);
	bn_free(n);
	ep2_free(T);
	ep2_free(Q1);
	ep2_free(Q2);
	ep2_free(ep2_tmp);
	ep2_free(neg_Q);
	fp12_free(f);
	fp12_free(g);
	fp12_free(f_num);
	fp12_free(f_den);
	fp12_free(g_num);
	fp12_free(g_den);
	fp12_free(fp12_tmp);
	return ;
}

static int sm9_barrett_bn_cmp(const sm9_barrett_bn_t a, const sm9_barrett_bn_t b)
{
	int i;
	for (i = 8; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

static void sm9_barrett_bn_add(sm9_barrett_bn_t r, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b)
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 9; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 8; i++) {
		r[i] &= 0xffffffff;
	}
}

static void sm9_barrett_bn_sub(sm9_barrett_bn_t ret, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b)
{
	sm9_barrett_bn_t r;
	int i;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 8; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	for (i = 0; i < 9; i++) {
		ret[i] = r[i];
	}
}

static int sm9_bn_cmp(const sm9_bn_t a, const sm9_bn_t b)
{
	int i;
	for (i = 7; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

static void sm9_bn_copy(sm9_bn_t r, const sm9_bn_t a)
{
	memcpy(r, a, sizeof(sm9_bn_t));
}

static void sm9_bn_sub(sm9_bn_t ret, const sm9_bn_t a, const sm9_bn_t b)
{
	int i;
	sm9_bn_t r;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 7; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	sm9_bn_copy(ret, r);
}



void sm9_fn_from_hash(bn_t h, const uint8_t Ha[40])
{
	uint64_t s[18] = {0};
	sm9_barrett_bn_t zh, zl, q;
	uint64_t w;
	int i, j;

	sm9_bn_t h_bn;

	/* s = Ha -> int */
	for (int i = 0; i < 10; i++) {
		for (int j = 0; j < 4; j++) {
			s[i] <<= 8;
			s[i] += Ha[4 * (9-i) + j];
		}
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 9; j++) {
			w += s[i + j] + zh[i] * SM9_MU_N_MINUS_ONE[j]; //
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 9] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[9 + i];
	}

	/* q = q * p mod (2^32)^9 */
	for (i = 0; i < 18; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM9_N_MINUS_ONE[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}

	/* h = zl - q (mod (2^32)^9) */

	if (sm9_barrett_bn_cmp(zl, q)) {
		sm9_barrett_bn_sub(zl, zl, q);
	} else {
		sm9_barrett_bn_t c = {0,0,0,0,0,0,0,0,0x100000000};
		sm9_barrett_bn_sub(q, c, q);
		sm9_barrett_bn_add(zl, q, zl);
	}

	for (i = 0; i < 8; i++) {
		h_bn[i] = zl[i];
	}

	h_bn[7] += (zl[8] << 32);

	/* while h >= (n-1) do: h = h - (n-1) */
	while (sm9_bn_cmp(h_bn, SM9_N_MINUS_ONE) >= 0) {
		sm9_bn_sub(h_bn, h_bn, SM9_N_MINUS_ONE);
	}

	// sm9_fn_add(h, h, SM9_ONE);
	bn_to_bn(h, h_bn);
	bn_add_dig(h,h,1);

}

#include <stdio.h>

int sm9_hash1(bn_t h1, const char *id, size_t idlen, uint8_t hid)
{
	SM3_CTX ctx;
	uint8_t prefix[1] = { SM9_HASH1_PREFIX };
	uint8_t ct1[4] = {0x00, 0x00, 0x00, 0x01};
	uint8_t ct2[4] = {0x00, 0x00, 0x00, 0x02};
	uint8_t Ha[64];

	sm3_init(&ctx);
	sm3_update(&ctx, prefix, sizeof(prefix));
	sm3_update(&ctx, (uint8_t *)id, idlen);
	sm3_update(&ctx, &hid, 1);
	sm3_update(&ctx, ct1, sizeof(ct1));
	sm3_finish(&ctx, Ha);

	sm3_init(&ctx);
	sm3_update(&ctx, prefix, sizeof(prefix));
	sm3_update(&ctx, (uint8_t *)id, idlen);
	sm3_update(&ctx, &hid, 1);
	sm3_update(&ctx, ct2, sizeof(ct2));
	sm3_finish(&ctx, Ha + 32);

	sm9_fn_from_hash(h1, Ha);
	return 1;
}

int sm9_exch_master_key_extract_key(SM9_ENC_MASTER_KEY *msk, const char *id, size_t idlen,
	SM9_ENC_KEY *key)
{
	bn_t t,group_order;

	bn_null(t);
	bn_new(t);
	bn_null(group_order);
	bn_new(group_order);
	g1_get_ord(group_order);

	// t1 = H1(ID || hid, N) + ke
	sm9_hash1(t, id, idlen, SM9_HID_EXCH);
	bn_add(t, t, msk->ke);
	//sm9_fn_add(t, t, msk->ks);
	if (bn_is_zero(t)) {
		error_print();
		return -1;
	}

	// t2 = ke * t1^-1
	
	bn_mod_inv(t,t,group_order);
	bn_mul(t,t,msk->ke);
	
	// de = t2 * P2
	ep2_mul_gen(key->de,t);
	ep_copy(key->Ppube,msk->Ppube);
	//key->Ppube = msk->Ppube;
	bn_free(t);
	bn_free(group_order);
	return 1;
}


int sm9_enc_master_key_extract_key(SM9_ENC_MASTER_KEY *msk, const char *id, size_t idlen,
	SM9_ENC_KEY *key)
{
	bn_t t,group_order;

	bn_null(t);
	bn_new(t);
	bn_null(group_order);
	bn_new(group_order);
	g1_get_ord(group_order);

	// t1 = H1(ID || hid, N) + ke
	sm9_hash1(t, id, idlen, SM9_HID_ENC);
	bn_add(t, t, msk->ke);
	//sm9_fn_add(t, t, msk->ks);
	if (bn_is_zero(t)) {
		error_print();
		return -1;
	}

	// t2 = ke * t1^-1
	
	bn_mod_inv(t,t,group_order);
	bn_mul(t,t,msk->ke);
	
	// de = t2 * P2
	ep2_mul_gen(key->de,t);
	ep_copy(key->Ppube,msk->Ppube);
	//key->Ppube = msk->Ppube;
	bn_free(t);
	bn_free(group_order);
	return 1;
}

int sm9_sign_master_key_extract_key(SM9_SIGN_MASTER_KEY *msk, const char *id, size_t idlen, SM9_SIGN_KEY *key)
{
	bn_t t,t1;

	bn_null(t);
	bn_new(t);
	bn_null(t1);
	bn_new(t1);

	// t1 = H1(ID || hid, N) + ks
	sm9_hash1(t, id, idlen, SM9_HID_SIGN);
	bn_add(t, t, msk->ks);
	//sm9_fn_add(t, t, msk->ks);
	if (bn_is_zero(t)) {
		// 这是一个严重问题，意味着整个msk都需要作废了
		error_print();
		return -1;
	}

	// t2 = ks * t1^-1
	//sm9_fn_inv(t, t);
	bn_read_str(t1,SM9_N,strlen(SM9_N),16);
	bn_mod_inv(t,t,t1);
	bn_mul(t,t,msk->ks);
	
	//sm9_fn_mul(t, t, msk->ks);
	// ds = t2 * P1
	ep_mul_gen(key->ds,t);
	//sm9_point_mul_generator(&key->ds, t);
	ep2_copy(key->Ppubs,msk->Ppubs);
	//key->Ppubs = msk->Ppubs;
	bn_free(t);
	bn_free(t1);
	return 1;
}

int sm9_do_sign_prestep1(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig)
{
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	sm9_bn_t r;
	fp12_t g;
	ep_t SM9_P1;
	fp_null(r);
	fp_new(r);
	fp12_null(g);
	fp12_new(g);

	ep_null(SM9_P1);
	ep_new(SM9_P1);
	
	g1_get_gen(SM9_P1);

	double begin, end;
	uint8_t bin[12 * RLC_FP_BYTES];
	uint8_t readbin[12 * RLC_FP_BYTES];
	// 测试pairing性能
	// PERFORMANCE_TEST_NEW("pairing", sm9_pairing_fast(g, key->Ppubs, SM9_P1));

	// A1: g = e(P1, Ppubs)

	sm9_pairing_fastest(g, key->Ppubs, SM9_P1);
	fp12_write_bin(bin, sizeof(bin), g, 0);
	//format_bytes(stdout, 0, 0, "bin written", bin, sizeof(bin));
	FILE *fp = NULL;
	fp = fopen("pairing_data.da","w");
	fwrite(bin,sizeof(uint8_t),sizeof(bin),fp);
	//fputs(bin,fp);
	fclose(fp);

	
	
	//fp12_read_bin(b, bin, sizeof(bin));	
	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&g, sizeof(g));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&tmp_ctx, sizeof(tmp_ctx));
	gmssl_secure_clear(Ha, sizeof(Ha));

	return 1;
}

int sm9_do_sign_prestep2(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig)
{
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	
	sm9_bn_t r;
	fp12_t g;
	ep_t SM9_P1;
	fp_null(r);
	fp_new(r);
	fp12_null(g);
	fp12_new(g);

	
	double begin, end;
	
	// 测试pairing性能
	// PERFORMANCE_TEST_NEW("pairing", sm9_pairing_fast(g, key->Ppubs, SM9_P1));

	// A1: g = e(P1, Ppubs)
	//sm9_pairing_fastest(g, key->Ppubs, SM9_P1);
	uint8_t bin2[12 * RLC_FP_BYTES];
	FILE *fp = NULL;
	
	
	fp = fopen("pairing_data.da","r");
	//fscanf(fp,"%c",bin2);
	fread(bin2,sizeof(uint8_t),sizeof(bin2),fp);
	//format_bytes(stdout, 0, 0, "bin read", bin2, sizeof(bin2));
	fclose(fp);
	fp12_read_bin(g, bin2, sizeof(bin2));	
//printf("??\n");

	do {
		// A2: rand r in [1, N-1]
		// if (fp_rand(r) != 1) {
		// 	error_print();
		// 	return -1;
		// }
		fp_rand(r);

		// 测试使用
		// sm9_fn_from_hex(r, "00033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE"); // for testing

		// A3: w = g^r
		fp12_pow(g, g, r);
		fp12_write_bin(wbuf, 32*12, g, 0);  // pack表示是否压缩

		// A4: h = H2(M || w, N)
		// hlen = 8*(5*bitlen(N)/32) = 8*40，8*40表示的是比特长度，也就是40字节
		sm3_update(&ctx, wbuf, sizeof(wbuf));  // 02||w
		tmp_ctx = ctx;
		sm3_update(&ctx, ct1, sizeof(ct1));  // 02||w||1
		sm3_finish(&ctx, Ha);                // Ha1
		sm3_update(&tmp_ctx, ct2, sizeof(ct2));  // 02||w||2
		sm3_finish(&tmp_ctx, Ha + 32);           // Ha2
		sm9_fn_from_hash(sig->h, Ha);  // 这里的参数Ha是大小为40的uint8_t数组, sig->h = (Ha mod (n-1)) + 1;
																																							
		// A5: l = (r - h) mod N, if l = 0, goto A2
		fp_sub(r, r, sig->h);
		// sm9_fn_sub(r, r, sig->h);
	} while (fp_is_zero(r));  // 如果r为0，返回到A2执行
	// } while (sm9_fn_is_zero(r));  // 如果r为0，返回到A2执行

	// A6: S = l * dsA
	ep_mul(sig->S, r, key->ds);
	// sm9_point_mul(&sig->S, r, &key->ds);

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&g, sizeof(g));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&tmp_ctx, sizeof(tmp_ctx));
	gmssl_secure_clear(Ha, sizeof(Ha));

	return 1;
}

//enc
int sm9_ciphertext_to_der(const ep_t C1, const uint8_t *c2, size_t c2len,
	const uint8_t c3[SM3_HMAC_SIZE], uint8_t **out, size_t *outlen)
{
	int en_type = SM9_ENC_TYPE_XOR;
	uint8_t c1[65];
	size_t len = 0;

	ep_write_bin(c1,65,C1,0);
	//sm9_point_to_uncompressed_octets(C1, c1);

	if (asn1_int_to_der(en_type, NULL, &len) != 1
		|| asn1_bit_octets_to_der(c1, sizeof(c1), NULL, &len) != 1
		|| asn1_octet_string_to_der(c3, SM3_HMAC_SIZE, NULL, &len) != 1
		|| asn1_octet_string_to_der(c2, c2len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(en_type, out, outlen) != 1
		|| asn1_bit_octets_to_der(c1, sizeof(c1), out, outlen) != 1
		|| asn1_octet_string_to_der(c3, SM3_HMAC_SIZE, out, outlen) != 1
		|| asn1_octet_string_to_der(c2, c2len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

//dec
int sm9_ciphertext_from_der(ep_t C1, const uint8_t **c2, size_t *c2len,
	const uint8_t **c3, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int en_type;
	const uint8_t *c1;
	size_t c1len;
	size_t c3len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&en_type, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&c1, &c1len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(c3, &c3len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(c2, c2len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (en_type != SM9_ENC_TYPE_XOR) {
		error_print();
		return -1;
	}
	if (c1len != 65) {
		error_print();
		return -1;
	}
	if (c3len != SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}
	ep_read_bin(C1,c1,65);
	return 1;
}

//sign
int sm9_signature_to_der(const SM9_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	
	uint8_t hbuf[32];
	uint8_t Sbuf[65];
	size_t len = 0;

	// sm9_fn_to_bytes(sig->h, hbuf);
	bn_write_bin(hbuf, 32, sig->h);
	//sm9_point_to_uncompressed_octets(&sig->S, Sbuf);
	ep_write_bin(Sbuf,65,sig->S,0);

	if (asn1_octet_string_to_der(hbuf, sizeof(hbuf), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Sbuf, sizeof(Sbuf), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(hbuf, sizeof(hbuf), out, outlen) != 1
		|| asn1_bit_octets_to_der(Sbuf, sizeof(Sbuf), out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

//verify
int sm9_signature_from_der(SM9_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *h;
	size_t hlen;
	const uint8_t *S;
	size_t Slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(&h, &hlen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&S, &Slen, &d, &dlen) != 1
		|| asn1_check(hlen == 32) != 1
		|| asn1_check(Slen == 65) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	bn_read_bin(sig->h,h,hlen);
	ep_read_bin(sig->S,S,Slen);

	return 1;
}

int sm9_kem_encrypt(const SM9_ENC_KEY *mpk, const char *id, size_t idlen,
	size_t klen, uint8_t *kbuf, ep_t C)
{	
	bn_t r,N;
	fp12_t w;
	bn_null(r);
	bn_new(r);
	bn_null(N);
	bn_new(N);
	fp12_null(w);
	fp12_new(w);

	ep2_t SM9_P2;
	ep2_null(SM9_P2);
	ep2_new(SM9_P2);
	g2_get_gen(SM9_P2);

	bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);
	uint8_t wbuf[32 * 12];
	uint8_t fubw[32 * 12];
	uint8_t cbuf[65];
	SM3_KDF_CTX kdf_ctx;

	// A1: Q = H1(ID||hid,N) * P1 + Ppube
	sm9_hash1(r, id, idlen, SM9_HID_ENC);
	ep_mul_gen(C,r);
	ep_add(C,C,mpk->Ppube);
	//just for correctness test
	char kem_r[] = "74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722";
	char enc_r[] = "AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C";
	
	do {
		// A2: rand r in [1, N-1]
		do{
			bn_rand(r,RLC_POS,256);
		}while((bn_cmp_dig(r,1) == -1) || (bn_cmp(r,N) == 1));
		
		bn_read_str(r,kem_r,strlen(kem_r),16);
		// A3: C1 = r * Q
		ep_mul(C,C,r);

		ep_write_bin(cbuf,65,C,0);
		//sm9_point_to_uncompressed_octets(C, cbuf);

		// A4: g = e(Ppube, P2)
		sm9_pairing_fastest(w,SM9_P2,mpk->Ppube);

		// A5: w = g^r
		fp12_pow_t(w, w, r);
		fp12_write_bin(wbuf,32*12,w,0);
		for(int i = 0;i<384;i++){
			fubw[(11-i/32)*32+i%32] = wbuf[i];
		}
		// A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
		sm3_kdf_init(&kdf_ctx, klen);
		sm3_kdf_update(&kdf_ctx, cbuf + 1, 64);
		sm3_kdf_update(&kdf_ctx, fubw, sizeof(fubw));
		sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
		sm3_kdf_finish(&kdf_ctx, kbuf);

	} while (mem_is_zero(kbuf, klen) == 1);

	bn_free(r);
	fp12_free(w);
	ep2_free(SM9_P2);
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(fubw, sizeof(fubw));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	//when using kem, klen = klen - datalen(20)

	// A7: output (K, C)
	return 1;
}

int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const ep_t C,
	size_t klen, uint8_t *kbuf)
{
	fp12_t w;
	fp12_null(w);
	fp12_new(w);
	uint8_t wbuf[32 * 12];
	uint8_t fubw[32 * 12];
	uint8_t cbuf[65];
	SM3_KDF_CTX kdf_ctx;

	// B1: check C in G1

	ep_write_bin(cbuf,65,C,0);
	//sm9_point_to_uncompressed_octets(C, cbuf);

	// B2: w = e(C, de);

	sm9_pairing_fastest(w, key->de, C);
	fp12_write_bin(wbuf, 32*12, w, 0);  // pack表示是否压缩
	// A4: h = H2(M || w, N)
	// hlen = 8*(5*bitlen(N)/32) = 8*40，8*40表示的是比特长度，也就是40字节
	for(int i = 0;i<384;i++){
		fubw[(11-i/32)*32+i%32] = wbuf[i];
	}

	// B3: K = KDF(C || w || ID, klen)
	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, cbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, fubw, sizeof(fubw));
	sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
	sm3_kdf_finish(&kdf_ctx, kbuf);

	if (mem_is_zero(kbuf, klen)) {
		error_print();
		return -1;
	}
	fp12_free(w);
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(fubw, sizeof(fubw));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// B4: output K
	return 1;
}
//aa

int sm9_do_encrypt(const SM9_ENC_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen,
	ep_t C1, uint8_t *c2, uint8_t c3[SM3_HMAC_SIZE])
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t K[inlen + 32];

	if (sm9_kem_encrypt(mpk, id, idlen, sizeof(K), K, C1) != 1) {
		error_print();
		return -1;
	}
	gmssl_memxor(c2, K, in, inlen);

	//sm3_hmac(K + inlen, 32, c2, inlen, c3);
	sm3_hmac_init(&hmac_ctx, K + inlen, SM3_HMAC_SIZE);
	sm3_hmac_update(&hmac_ctx, c2, inlen);
	sm3_hmac_finish(&hmac_ctx, c3);
	gmssl_secure_clear(&hmac_ctx, sizeof(hmac_ctx));
	return 1;

}

int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const ep_t C1, const uint8_t *c2, size_t c2len, const uint8_t c3[SM3_HMAC_SIZE],
	uint8_t *out)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t k[SM9_MAX_PLAINTEXT_SIZE + SM3_HMAC_SIZE];
	uint8_t mac[SM3_HMAC_SIZE];

	if (c2len > SM9_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (sm9_kem_decrypt(key, id, idlen, C1, sizeof(k), k) != 1) {
		error_print();
		return -1;
	}
	//sm3_hmac(k + c2len, SM3_HMAC_SIZE, c2, c2len, mac);
	sm3_hmac_init(&hmac_ctx, k + c2len, SM3_HMAC_SIZE);
	sm3_hmac_update(&hmac_ctx, c2, c2len);
	sm3_hmac_finish(&hmac_ctx, mac);
	gmssl_secure_clear(&hmac_ctx, sizeof(hmac_ctx));

	if (gmssl_secure_memcmp(c3, mac, sizeof(mac)) != 0) {
		error_print();
		return -1;
	}
	gmssl_memxor(out, k, c2, c2len);
	return 1;
}

int sm9_exchange_A1(const SM9_ENC_KEY *usr, const char *id, size_t idlen,ep_t Ra,bn_t ra){
	
	bn_t N;
	bn_null(N);
	bn_new(N);

	sm9_hash1(ra, id, idlen, SM9_HID_EXCH);
	ep_mul_gen(Ra,ra);
	ep_add(Ra,Ra,usr->Ppube);
	//just for correctness test
	char exch_ra[] = "5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8";

	// A2: rand r in [1, N-1]
	bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);
	do{
		bn_rand(ra,RLC_POS,256);
	}while((bn_cmp_dig(ra,1) == -1) || (bn_cmp(ra,N) == 1));
	bn_read_str(ra,exch_ra,strlen(exch_ra),16);
	// A3: R = r * Q
	ep_mul(Ra,Ra,ra);
	return 1;
}

int sm9_exchange_B1_without_check(const SM9_ENC_KEY *usr,fp12_t g_1,fp12_t g_2,fp12_t g_3,ep_t Ra,ep_t Rb,const char *ida,size_t idalen,const char *idb, size_t idblen,size_t klen,uint8_t *kbuf){

	SM3_KDF_CTX kdf_ctx;

	g2_t gen2;
	g2_null(gen2);
	g2_new(gen2);	

	ep_t tmp;
	ep_null(tmp);
	ep_new(tmp);

	g2_get_gen(gen2);

	bn_t r,N;
	bn_null(r);
	bn_new(r);
	bn_null(N);
	bn_new(N);

	uint8_t g1buf[32 * 12];
	uint8_t g2buf[32 * 12];
	uint8_t g3buf[32 * 12];
	uint8_t g1_real[32 * 12];
	uint8_t g2_real[32 * 12];
	uint8_t g3_real[32 * 12];

	uint8_t Rbbuf[65];
	uint8_t Rabuf[65];
	
	uint8_t eighty_two[1] = {0x82};

	sm9_hash1(r, ida, idalen, SM9_HID_EXCH);
	ep_mul_gen(Rb,r);
	ep_add(Rb,Rb,usr->Ppube);
	//just for correctness test
	char exch_rb[] = "18B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE";

	// A2: rand r in [1, N-1]
	bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);
	do{
		bn_rand(r,RLC_POS,256);
	}while((bn_cmp_dig(r,1) == -1) || (bn_cmp(r,N) == 1));
	bn_read_str(r,exch_rb,strlen(exch_rb),16);
	// A3: R = r * Q
	ep_mul(Rb,Rb,r);

	ep_write_bin(Rabuf,65,Ra,0);
	ep_write_bin(Rbbuf,65,Rb,0);

	sm9_pairing_fastest(g_1,usr->de,Ra);
	fp12_pow_t(g_3,g_1,r);

	//sm9_pairing_fastest(g_2,gen2,usr->Ppube);
	//fp12_pow_t(g_2,g_2,r);
	ep_mul(tmp,usr->Ppube,r);
	sm9_pairing_fastest(g_2,gen2,tmp);

	fp12_write_bin(g1buf,32*12,g_1,0);
	fp12_write_bin(g2buf,32*12,g_2,0);
	fp12_write_bin(g3buf,32*12,g_3,0);

	for(int i = 0;i<384;i++){
		g1_real[(11-i/32)*32+i%32] = g1buf[i];
		g2_real[(11-i/32)*32+i%32] = g2buf[i];
		g3_real[(11-i/32)*32+i%32] = g3buf[i];
	}

	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)ida, idalen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)idb, idblen);
	sm3_kdf_update(&kdf_ctx, Rabuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, Rbbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, g1_real,sizeof(g1_real));
	sm3_kdf_update(&kdf_ctx, g2_real,sizeof(g2_real));
	sm3_kdf_update(&kdf_ctx, g3_real,sizeof(g3_real));
	sm3_kdf_finish(&kdf_ctx, kbuf);

	ep_free(tmp);
	g2_free(gen2);
	bn_free(r);
	bn_free(N);

	return 1;
}

int sm9_exchange_B1(const SM9_ENC_KEY *usr,fp12_t g_1,fp12_t g_2,fp12_t g_3,ep_t Ra,ep_t Rb,const char *ida,size_t idalen,const char *idb, size_t idblen,size_t klen,uint8_t *kbuf,size_t sblen,size_t sb){

	if( sblen < 32 ){
		RLC_THROW(ERR_NO_BUFFER);
		return -1;
	}

	SM3_KDF_CTX kdf_ctx;
	SM3_CTX sb_ctx;

	g2_t gen2;
	g2_null(gen2);
	g2_new(gen2);	

	ep_t tmp;
	ep_null(tmp);
	ep_new(tmp);

	g2_get_gen(gen2);

	bn_t r,N;
	bn_null(r);
	bn_new(r);
	bn_null(N);
	bn_new(N);

	uint8_t g1buf[32 * 12];
	uint8_t g2buf[32 * 12];
	uint8_t g3buf[32 * 12];
	uint8_t g1_real[32 * 12];
	uint8_t g2_real[32 * 12];
	uint8_t g3_real[32 * 12];

	uint8_t Rbbuf[65];
	uint8_t Rabuf[65];
	
	uint8_t eighty_two[1] = {0x82};

	sm9_hash1(r, ida, idalen, SM9_HID_EXCH);
	ep_mul_gen(Rb,r);
	ep_add(Rb,Rb,usr->Ppube);
	//just for correctness test
	char exch_rb[] = "18B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE";

	// A2: rand r in [1, N-1]
	bn_read_str(N,SM9_N,strlen(SM9_N),16);
	bn_sub_dig(N,N,1);
	do{
		bn_rand(r,RLC_POS,256);
	}while((bn_cmp_dig(r,1) == -1) || (bn_cmp(r,N) == 1));
	bn_read_str(r,exch_rb,strlen(exch_rb),16);
	// A3: R = r * Q
	ep_mul(Rb,Rb,r);

	ep_write_bin(Rabuf,65,Ra,0);
	ep_write_bin(Rbbuf,65,Rb,0);

	sm9_pairing_fastest(g_1,usr->de,Ra);
	fp12_pow_t(g_3,g_1,r);

	//sm9_pairing_fastest(g_2,gen2,usr->Ppube);
	//fp12_pow_t(g_2,g_2,r);
	ep_mul(tmp,usr->Ppube,r);
	sm9_pairing_fastest(g_2,gen2,tmp);

	fp12_write_bin(g1buf,32*12,g_1,0);
	fp12_write_bin(g2buf,32*12,g_2,0);
	fp12_write_bin(g3buf,32*12,g_3,0);

	for(int i = 0;i<384;i++){
		g1_real[(11-i/32)*32+i%32] = g1buf[i];
		g2_real[(11-i/32)*32+i%32] = g2buf[i];
		g3_real[(11-i/32)*32+i%32] = g3buf[i];
	}

	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)ida, idalen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)idb, idblen);
	sm3_kdf_update(&kdf_ctx, Rabuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, Rbbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, g1_real,sizeof(g1_real));
	sm3_kdf_update(&kdf_ctx, g2_real,sizeof(g2_real));
	sm3_kdf_update(&kdf_ctx, g3_real,sizeof(g3_real));
	sm3_kdf_finish(&kdf_ctx, kbuf);

	sm3_init(&sb_ctx);
    sm3_update(&sb_ctx, g2_real,sizeof(g2_real));
	sm3_update(&sb_ctx, g3_real,sizeof(g3_real));
	sm3_update(&sb_ctx, (uint8_t *)ida, idalen);
	sm3_update(&sb_ctx, (uint8_t *)idb, idblen);
	sm3_update(&sb_ctx, Rabuf + 1, 64);
	sm3_update(&sb_ctx, Rbbuf + 1, 64);
	sm3_finish(&sb_ctx, sb);

	sm3_init(&sb_ctx);
	sm3_update(&sb_ctx, eighty_two,sizeof(eighty_two));
	sm3_update(&sb_ctx, g1_real,sizeof(g1_real));
	sm3_update(&sb_ctx, sb,sblen);
	sm3_finish(&sb_ctx, sb);

	ep_free(tmp);
	g2_free(gen2);
	bn_free(r);
	bn_free(N);

	return 1;
}

int sm9_exchange_A2_without_check(const SM9_ENC_KEY *usr,ep_t Ra,ep_t Rb,bn_t ra,const char *ida,size_t idalen,const char *idb, size_t idblen,size_t klen,uint8_t *kbuf){

	SM3_KDF_CTX kdf_ctx;

	fp12_t g_1;
	fp12_null(g_1);
	fp12_new(g_1);
	fp12_t g_3;
	fp12_null(g_3);
	fp12_new(g_3);
	fp12_t g_2;
	fp12_null(g_2);
	fp12_new(g_2);

	g2_t gen2;
	g2_null(gen2);
	g2_new(gen2);	
	g2_get_gen(gen2);

	ep_t tmp;
	ep_null(tmp);
	ep_new(tmp);

	uint8_t g1buf[32 * 12];
	uint8_t g2buf[32 * 12];
	uint8_t g3buf[32 * 12];
	uint8_t g1_real[32 * 12];
	uint8_t g2_real[32 * 12];
	uint8_t g3_real[32 * 12];
	uint8_t Rbbuf[65];
	uint8_t Rabuf[65];
	uint8_t dgst[32];

	//sm9_pairing_fastest(g_1,gen2,usr->Ppube);
	//fp12_pow_t(g_1,g_1,ra);
	//PERFORMANCE_TEST_NEW("e^r",sm9_pairing_fastest(g_1,gen2,usr->Ppube);fp12_pow_t(g_1,g_1,ra));
	//PERFORMANCE_TEST_NEW("e^r faster",ep_mul(tmp,usr->Ppube,ra);sm9_pairing_fastest(g_1,gen2,tmp));
	ep_mul(tmp,usr->Ppube,ra);
	sm9_pairing_fastest(g_1,gen2,tmp);

	//PERFORMANCE_TEST_NEW("e^r",sm9_pairing_fastest(g_2,usr->de,Rb);fp12_pow_t(g_3,g_2,ra));
	sm9_pairing_fastest(g_2,usr->de,Rb);
	fp12_pow_t(g_3,g_2,ra);
	//PERFORMANCE_TEST_NEW("e^r low",sm9_pairing_fastest(g_2,usr->de,Rb);ep_mul(tmp,Rb,ra);sm9_pairing_fastest(g_3,usr->de,tmp));
	
	fp12_write_bin(g1buf,32*12,g_1,0);
	fp12_write_bin(g2buf,32*12,g_2,0);
	fp12_write_bin(g3buf,32*12,g_3,0);

	for(int i = 0;i<384;i++){
		g1_real[(11-i/32)*32+i%32] = g1buf[i];
		g2_real[(11-i/32)*32+i%32] = g2buf[i];
		g3_real[(11-i/32)*32+i%32] = g3buf[i];
	}

	ep_write_bin(Rabuf,65,Ra,0);
	ep_write_bin(Rbbuf,65,Rb,0);

	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)ida, idalen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)idb, idblen);
	sm3_kdf_update(&kdf_ctx, Rabuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, Rbbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, g1_real,sizeof(g1_real));
	sm3_kdf_update(&kdf_ctx, g2_real,sizeof(g2_real));
	sm3_kdf_update(&kdf_ctx, g3_real,sizeof(g3_real));
	sm3_kdf_finish(&kdf_ctx, kbuf);
	printf("session key is\n");
	print_bytes(kbuf,klen);

	fp12_free(g_1);
	fp12_free(g_2);
	fp12_free(g_3);
	g2_free(gen2);
	ep_free(tmp);
	return 1;

}

int sm9_exchange_A2(const SM9_ENC_KEY *usr,ep_t Ra,ep_t Rb,bn_t ra,const char *ida,size_t idalen,const char *idb, size_t idblen,size_t klen,uint8_t *kbuf,size_t salen,uint8_t *sa,size_t datalen,uint8_t *data){

	if(salen < 32 || datalen < 32){
		RLC_THROW(ERR_NO_BUFFER);
		return -1;
	}

	SM3_KDF_CTX kdf_ctx;
	SM3_CTX sa_ctx;

	fp12_t g_1;
	fp12_null(g_1);
	fp12_new(g_1);
	fp12_t g_3;
	fp12_null(g_3);
	fp12_new(g_3);
	fp12_t g_2;
	fp12_null(g_2);
	fp12_new(g_2);

	g2_t gen2;
	g2_null(gen2);
	g2_new(gen2);	
	g2_get_gen(gen2);

	ep_t tmp;
	ep_null(tmp);
	ep_new(tmp);

	uint8_t g1buf[32 * 12];
	uint8_t g2buf[32 * 12];
	uint8_t g3buf[32 * 12];
	uint8_t g1_real[32 * 12];
	uint8_t g2_real[32 * 12];
	uint8_t g3_real[32 * 12];
	uint8_t Rbbuf[65];
	uint8_t Rabuf[65];
	uint8_t dgst[32];

	uint8_t eighty_two_and_three[2] = {0x82,0x83};

	//sm9_pairing_fastest(g_1,gen2,usr->Ppube);
	//fp12_pow_t(g_1,g_1,ra);
	//PERFORMANCE_TEST_NEW("e^r",sm9_pairing_fastest(g_1,gen2,usr->Ppube);fp12_pow_t(g_1,g_1,ra));
	//PERFORMANCE_TEST_NEW("e^r faster",ep_mul(tmp,usr->Ppube,ra);sm9_pairing_fastest(g_1,gen2,tmp));
	ep_mul(tmp,usr->Ppube,ra);
	sm9_pairing_fastest(g_1,gen2,tmp);

	//PERFORMANCE_TEST_NEW("e^r",sm9_pairing_fastest(g_2,usr->de,Rb);fp12_pow_t(g_3,g_2,ra));
	sm9_pairing_fastest(g_2,usr->de,Rb);
	fp12_pow_t(g_3,g_2,ra);
	//PERFORMANCE_TEST_NEW("e^r low",sm9_pairing_fastest(g_2,usr->de,Rb);ep_mul(tmp,Rb,ra);sm9_pairing_fastest(g_3,usr->de,tmp));
	
	fp12_write_bin(g1buf,32*12,g_1,0);
	fp12_write_bin(g2buf,32*12,g_2,0);
	fp12_write_bin(g3buf,32*12,g_3,0);

	for(int i = 0;i<384;i++){
		g1_real[(11-i/32)*32+i%32] = g1buf[i];
		g2_real[(11-i/32)*32+i%32] = g2buf[i];
		g3_real[(11-i/32)*32+i%32] = g3buf[i];
	}

	ep_write_bin(Rabuf,65,Ra,0);
	ep_write_bin(Rbbuf,65,Rb,0);

	sm3_init(&sa_ctx);
    sm3_update(&sa_ctx, g2_real,sizeof(g2_real));
	sm3_update(&sa_ctx, g3_real,sizeof(g3_real));
	sm3_update(&sa_ctx, (uint8_t *)ida, idalen);
	sm3_update(&sa_ctx, (uint8_t *)idb, idblen);
	sm3_update(&sa_ctx, Rabuf + 1, 64);
	sm3_update(&sa_ctx, Rbbuf + 1, 64);
	sm3_finish(&sa_ctx, dgst);

	sm3_init(&sa_ctx);
	sm3_update(&sa_ctx, eighty_two_and_three+1,sizeof(eighty_two_and_three)/2);
	sm3_update(&sa_ctx, g1_real,sizeof(g1_real));
	sm3_update(&sa_ctx, dgst,sizeof(dgst));
	sm3_finish(&sa_ctx, sa);

	sm3_init(&sa_ctx);
	sm3_update(&sa_ctx, eighty_two_and_three,sizeof(eighty_two_and_three)/2);
	sm3_update(&sa_ctx, g1_real,sizeof(g1_real));
	sm3_update(&sa_ctx, dgst,sizeof(dgst));
	sm3_finish(&sa_ctx, dgst);

	if(memcmp(dgst,data,32) != 0){
		printf("ERROR:key exchange fail!\n");
		return -1;
	}

	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)ida, idalen);
	sm3_kdf_update(&kdf_ctx, (uint8_t *)idb, idblen);
	sm3_kdf_update(&kdf_ctx, Rabuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, Rbbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, g1_real,sizeof(g1_real));
	sm3_kdf_update(&kdf_ctx, g2_real,sizeof(g2_real));
	sm3_kdf_update(&kdf_ctx, g3_real,sizeof(g3_real));
	sm3_kdf_finish(&kdf_ctx, kbuf);
	//printf("session key is:\n");
	//print_bytes(kbuf,klen);

	fp12_free(g_1);
	fp12_free(g_2);
	fp12_free(g_3);
	g2_free(gen2);
	ep_free(tmp);
	return 1;
}

int sm9_exchange_B2(fp12_t g_1,fp12_t g_2,fp12_t g_3,ep_t Ra,ep_t Rb,const char *ida,size_t idalen,const char *idb, size_t idblen,size_t datalen,uint8_t *data){
	if( datalen < 32 ){
		RLC_THROW(ERR_NO_BUFFER);
		return -1;
	}
	SM3_CTX sb_ctx;

	uint8_t Rbbuf[65];
	uint8_t Rabuf[65];
	uint8_t g1buf[32 * 12];
	uint8_t g2buf[32 * 12];
	uint8_t g3buf[32 * 12];
	uint8_t g1_real[32 * 12];
	uint8_t g2_real[32 * 12];
	uint8_t g3_real[32 * 12];
	uint8_t dgst[32];
	uint8_t eighty_three[1] = {0x83};


	ep_write_bin(Rabuf,65,Ra,0);
	ep_write_bin(Rbbuf,65,Rb,0);

	fp12_write_bin(g1buf,32*12,g_1,0);
	fp12_write_bin(g2buf,32*12,g_2,0);
	fp12_write_bin(g3buf,32*12,g_3,0);

	for(int i = 0;i<384;i++){
		g1_real[(11-i/32)*32+i%32] = g1buf[i];
		g2_real[(11-i/32)*32+i%32] = g2buf[i];
		g3_real[(11-i/32)*32+i%32] = g3buf[i];
	}

	sm3_init(&sb_ctx);
    sm3_update(&sb_ctx, g2_real,sizeof(g2_real));
	sm3_update(&sb_ctx, g3_real,sizeof(g3_real));
	sm3_update(&sb_ctx, (uint8_t *)ida, idalen);
	sm3_update(&sb_ctx, (uint8_t *)idb, idblen);
	sm3_update(&sb_ctx, Rabuf + 1, 64);
	sm3_update(&sb_ctx, Rbbuf + 1, 64);
	sm3_finish(&sb_ctx, dgst);
	sm3_init(&sb_ctx);
	sm3_update(&sb_ctx, eighty_three,sizeof(eighty_three));
	sm3_update(&sb_ctx, g1_real,sizeof(g1_real));
	sm3_update(&sb_ctx, dgst,sizeof(dgst));
	sm3_finish(&sb_ctx, dgst);

	if(memcmp(dgst,data,32) != 0){
		printf("ERROR:key exchange fail!\n");
		return -1;
	}
	else{
		//printf("key exchange sussess!\n");
	}
	return 1;
}

int sm9_encrypt(const SM9_ENC_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	ep_t C1;
	ep_null(C1);
	ep_new(C1);
	uint8_t c2[inlen];
	uint8_t c3[SM3_HMAC_SIZE];

	if (sm9_do_encrypt(mpk, id, idlen, in, inlen, C1, c2, c3) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm9_ciphertext_to_der(C1, c2, inlen, c3, &out, outlen) != 1) { // FIXME: when out == NULL	
		error_print();
		return -1;
	}
	ep_free(C1);
	return 1;
}

int sm9_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	ep_t C1;
	ep_null(C1);
	ep_new(C1);
	const uint8_t *c2;
	size_t c2len;
	const uint8_t *c3;

	if (sm9_ciphertext_from_der(C1, &c2, &c2len, &c3, &in, &inlen) != 1
		|| asn1_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}

	*outlen = c2len;
	if (!out) {
		return 1;
	}
	if (sm9_do_decrypt(key, id, idlen, C1, c2, c2len, c3, out) != 1) {
		error_print();
		return -1;
	}
	ep_free(C1);
	return 1;
}

int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig)
{
	uint8_t wbuf[32 * 12];
	uint8_t fubw[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	bn_t r;
	bn_t ord;
	fp12_t g,w;
	ep_t SM9_P1;
	bn_null(r);
	bn_new(r);
	bn_null(ord);
	bn_new(ord);

	fp12_null(g);
	fp12_new(g);

	fp12_null(w);
	fp12_new(w);

	ep_null(SM9_P1);
	ep_new(SM9_P1);
	
	g1_get_gen(SM9_P1);
	g1_get_ord(ord);

	char rr[] = "33C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE";
	//sm9_bn_t rr = {0xDC4B1CBE,0xED648835,0xC662337A,0x2ED15975,0xD0096502,0x813203DF,0x16B06704,0x033C86};
	// 测试pairing性能
	// PERFORMANCE_TEST_NEW("pairing", sm9_pairing_fast(g, key->Ppubs, SM9_P1));

	// A1: g = e(P1, Ppubs)
	sm9_pairing_fastest(g, key->Ppubs, SM9_P1);
	do {
		// A2: rand r in [1, N-1]
		// if (fp_rand(r) != 1) {
		// 	error_print();
		// 	return -1;
		// }
		//fp_rand(r);
		bn_read_str(r,rr,strlen(rr),16);
		// 测试使用
		//sm9_fn_from_hex(r, "00033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE"); // for testing

		// A3: w = g^r
		fp12_pow_t(w, g, r);
		fp12_write_bin(wbuf, 32*12, w, 0);  // pack表示是否压缩
		// A4: h = H2(M || w, N)
		// hlen = 8*(5*bitlen(N)/32) = 8*40，8*40表示的是比特长度，也就是40字节
		
		for(int i = 0;i<384;i++){
			fubw[(11-i/32)*32+i%32] = wbuf[i];
		}
		sm3_update(&ctx, fubw, sizeof(fubw));  // 02||w
		tmp_ctx = ctx;

		sm3_update(&ctx, ct1, sizeof(ct1));  // 02||w||1
		sm3_finish(&ctx, Ha);                // Ha1
		sm3_update(&tmp_ctx, ct2, sizeof(ct2));  // 02||w||2
		sm3_finish(&tmp_ctx, Ha + 32);           // Ha2
		sm9_fn_from_hash(sig->h, Ha);  // 这里的参数Ha是大小为40的uint8_t数组, sig->h = (Ha mod (n-1)) + 1;																											
		// A5: l = (r - h) mod N, if l = 0, goto A2
		bn_sub(r, r, sig->h);
		if(r->sign == RLC_NEG){
			bn_add(r,r,ord);
		}
		// sm9_fn_sub(r, r, sig->h);
	} while (bn_is_zero(r));  // 如果r为0，返回到A2执行
	// } while (sm9_fn_is_zero(r));  // 如果r为0，返回到A2执行
	// A6: S = l * dsA
	ep_mul(sig->S, key->ds,r);
	// sm9_point_mul(&sig->S, r, &key->ds);

	bn_free(r);
	bn_free(ord);
	fp12_free(g);
	fp12_free(w);
	ep_free(SM9_P1);
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(fubw, sizeof(fubw));
	gmssl_secure_clear(&tmp_ctx, sizeof(tmp_ctx));
	gmssl_secure_clear(Ha, sizeof(Ha));

	return 1;
}

// sm9 签名
int sm9_sign_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = { SM9_HASH2_PREFIX };
	sm3_init(&ctx->sm3_ctx);
	// sm3_ctx以0x02开头
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen)
{
	SM9_SIGNATURE signature;
	
	bn_null(signature.h);
	bn_new(signature.h);
	ep_null(signature.S);
	ep_new(signature.S);
	// 测试sm_do_sign性能
	// PERFORMANCE_TEST_NEW("sm9_do_sign", sm9_do_sign(key, &ctx->sm3_ctx, &signature));

	// 签名
	if (sm9_do_sign(key, &ctx->sm3_ctx, &signature) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;

	// SM9_SIGNATURE 转成 字节数组
	if (sm9_signature_to_der(&signature, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	bn_free(signature.h);
	ep_free(signature.S);
	return 1;
}


int sm9_sign_finish_precompute_step1(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen)
{
	SM9_SIGNATURE signature;

	// 测试sm_do_sign性能
	// PERFORMANCE_TEST_NEW("sm9_do_sign", sm9_do_sign(key, &ctx->sm3_ctx, &signature));

	// 签名
	sm9_do_sign_prestep1(key, &ctx->sm3_ctx, &signature);
	return 1;
}
int sm9_sign_finish_precompute_step2(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen)
{
	SM9_SIGNATURE signature;

	// 测试sm_do_sign性能
	// PERFORMANCE_TEST_NEW("sm9_do_sign", sm9_do_sign(key, &ctx->sm3_ctx, &signature));

	// 签名
	if (sm9_do_sign_prestep2(key, &ctx->sm3_ctx, &signature) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;
	
	// SM9_SIGNATURE 转成 字节数组
	if (sm9_signature_to_der(&signature, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_do_verify(const SM9_SIGN_KEY *mpk, const char *id, size_t idlen,
	const SM3_CTX *sm3_ctx, const SM9_SIGNATURE *sig)
{	
	bn_t h1,h2;
	bn_null(h1);
	bn_new(h1);
	bn_null(h2);
	bn_new(h2);

	fp12_t g;
	fp12_t t;
	fp12_t u;
	fp12_t w;

	fp12_null(g);
	fp12_null(t);
	fp12_null(u);
	fp12_null(w);
	fp12_new(g);
	fp12_new(t);
	fp12_new(u);
	fp12_new(w);

	ep2_t P;
	ep2_null(P);
	ep2_new(P);
	
	uint8_t wbuf[32 * 12];
	uint8_t fubw[32*12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t hid[4] = {0,0,0,1};
	uint8_t Ha[64];

	ep_t SM9_P1;
	ep_null(SM9_P1);
	ep_new(SM9_P1);
	g1_get_gen(SM9_P1);

	// B1: check h in [1, N-1]

	// B2: check S in G1

	// B3: g = e(P1, Ppubs)

	sm9_pairing_fastest(g, mpk->Ppubs, SM9_P1);
	// B4: t = g^h
	fp12_pow_t(t, g, sig->h);

	// B5: h1 = H1(ID || hid, N)
	sm9_hash1(h1, id, idlen, SM9_HID_SIGN);
	// B6: P = h1 * P2 + Ppubs
	//sm9_twist_point_mul_generator(&P, h1);
	
	ep2_mul_gen(P,h1);
	ep2_add(P, P, mpk->Ppubs);

	// B7: u = e(S, P)
	sm9_pairing_fastest(u, P, sig->S);


	// B8: w = u * t
	fp12_mul_t(w, u, t);
	//sm9_fp12_to_bytes(w, wbuf);
	fp12_write_bin(wbuf, 32*12, w, 0);

	for(int i = 0;i<384;i++){
		fubw[(11-i/32)*32+i%32] = wbuf[i];
	}

	// B9: h2 = H2(M || w, N), check h2 == h
	sm3_update(&ctx, fubw, sizeof(fubw));
	tmp_ctx = ctx;
	sm3_update(&ctx, ct1, sizeof(ct1));
	sm3_finish(&ctx, Ha);
	sm3_update(&tmp_ctx, ct2, sizeof(ct2));
	sm3_finish(&tmp_ctx, Ha + 32);
	sm9_fn_from_hash(h2, Ha);

	if (bn_cmp(h2, sig->h) != 0) {
		return 0;
	}

	bn_free(h1);
	bn_free(h2);
	fp12_free(g);
	fp12_free(t);
	fp12_free(u);
	fp12_free(w);
	ep_free(SM9_P1);
	ep2_free(P);

	return 1;
}

int sm9_verify_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = { SM9_HASH2_PREFIX };
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,
	const SM9_SIGN_KEY *mpk, const char *id, size_t idlen)
{
	int ret;
	SM9_SIGNATURE signature;
	bn_null(signature.h);
	bn_new(signature.h);
	ep_null(signature.S);
	ep_new(signature.S);

	if (sm9_signature_from_der(&signature, &sig, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}

	if ((ret = sm9_do_verify(mpk, id, idlen, &ctx->sm3_ctx, &signature)) < 0) {
		error_print();
		return -1;
	}
	//printf("\nsignature.h2 is :\n");
	//bn_print(signature.h);
	bn_free(signature.h);
	ep_free(signature.S);
	return ret;
}

//----------------------------speed test modules-------------------

int speedtest_sm9_sign_verify(){
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
	PERFORMANCE_TEST_NEW("RELIC SM9_signature ",sm9_sign_finish(&ctx, &sign_key, sig, &siglen));
	//sm9_sign_finish(&ctx, &sign_key, sig, &siglen);
	//format_bytes(stdout, 0, 0, "signature", sig, siglen);

	sm9_verify_init(&ctx);
	sm9_verify_update(&ctx, data, datalen);
	//if (sm9_verify_finish(&ctx, sig, siglen, &sign_master,(char *)id, idlen) != 1) goto err; ++j;
	PERFORMANCE_TEST_NEW("RELIC SM9_verification ",sm9_verify_finish(&ctx, sig, siglen, &sign_key,(char *)id, idlen));
	//format_bytes(stdout, 0, 0, "\nverified signature", sig, siglen);
	//write_file("output.txt",sig,siglen);

	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	sign_master_key_free(&sign_master);
	sign_user_key_free(&sign_key);
	error_print();
	return -1;
}


int speedtest_sm9_exchange() {

	SM9_ENC_MASTER_KEY msk;
	SM9_ENC_KEY alice_key;
    SM9_ENC_KEY bob_key;

    ep_t Ra;
    ep_null(Ra);
    ep_new(Ra);
    ep_t Rb;
    ep_null(Rb);
    ep_new(Rb);

    bn_t ra;
    bn_null(ra);
    bn_new(ra);

    fp12_t g1,g2,g3;
    fp12_null(g1);
	fp12_new(g1);
	fp12_null(g3);
	fp12_new(g3);
	fp12_null(g2);
	fp12_new(g2);

    char ke[] = "2E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F";
    //enc_master_key_init(&msk);
    enc_master_key_read(&msk,ke,strlen(ke),16);
    enc_user_key_init(&bob_key);
    enc_user_key_init(&alice_key);

	int j = 1;

    uint8_t kbuf[16] = {0};
    uint8_t sa[32];
    uint8_t sb[32];
    int salen = 32;
    int sblen = 32;
    int klen = sizeof(kbuf);

    //Alice
    uint8_t IDA[5] = {0x41,0x6C,0x69,0x63,0x65};
	//Bob
	uint8_t IDB[3] = {0x42, 0x6F, 0x62};

	if (sm9_exch_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &bob_key) < 0) goto err; ++j;
	if (sm9_exch_master_key_extract_key(&msk, (char *)IDA, sizeof(IDA), &alice_key) < 0) goto err; ++j;

	PERFORMANCE_TEST_NEW("RELIC SM9_exchange_A1-A4 ",sm9_exchange_A1(&alice_key, (char *)IDB, sizeof(IDB),Ra,ra));
	PERFORMANCE_TEST_NEW("RELIC SM9_exchange_B1-B7 ",sm9_exchange_B1(&bob_key,g1,g2,g3,Ra,Rb,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),klen,kbuf,sblen,sb));
	PERFORMANCE_TEST_NEW("RELIC SM9_exchange_A5-A8 ",sm9_exchange_A2(&alice_key,Ra,Rb,ra,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),klen,kbuf,salen,sa,sblen,sb));
	PERFORMANCE_TEST_NEW("RELIC SM9_exchange_B8 ",sm9_exchange_B2(g1,g2,g3,Ra,Rb,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),salen,sa));

	//sm9_exchange_A1(&alice_key, (char *)IDB, sizeof(IDB),Ra,ra);
    //sm9_exchange_B1(&bob_key,g1,g2,g3,Ra,Rb,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),klen,kbuf,sblen,sb);
    //sm9_exchange_A2(&alice_key,Ra,Rb,ra,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),klen,kbuf,salen,sa,sblen,sb);
    //sm9_exchange_B2(g1,g2,g3,Ra,Rb,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),salen,sa);
	printf("%s() ok\n", __FUNCTION__);
    enc_master_key_free(&msk);
    enc_user_key_free(&bob_key);
    enc_user_key_free(&alice_key);
    ep_free(Ra);
    ep_free(Rb);
    bn_free(ra);
    fp12_free(g3);
    fp12_free(g2);
    fp12_free(g1);
	return 1;
err:
    enc_master_key_free(&msk);
    enc_user_key_free(&bob_key);
    enc_user_key_free(&alice_key);
    ep_free(Ra);
    ep_free(Rb);
    bn_free(ra);
    fp12_free(g3);
    fp12_free(g2);
    fp12_free(g1);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

int speedtest_sm9_kem_kdm() {
	SM9_ENC_MASTER_KEY msk;
	SM9_ENC_KEY enc_key;

    //enc_master_key_init(&msk);
    //enc_user_key_init(&enc_key);
	
	ep_null(enc_key.Ppube);
	ep_new(enc_key.Ppube);
	ep2_null(enc_key.de);
	ep2_new(enc_key.de);

	ep_t C;
	ep_null(C);
	ep_new(C);

    uint8_t out[1000] = {0};
	size_t outlen = 0;
	int j = 1;
	uint8_t kbuf[287];
	size_t klen = 32;
	//Bob
	uint8_t IDB[3] = {0x42, 0x6F, 0x62};

	uint8_t testbuf[128];
	int tlen = 128;

	enc_master_key_init(&msk);

	if (sm9_enc_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &enc_key) < 0) goto err; ++j;

    PERFORMANCE_TEST_NEW("RELIC SM9_kem_encrypt ",sm9_kem_encrypt(&msk, (char *)IDB, sizeof(IDB), klen, kbuf, C) );	
	//sm9_kem_encrypt(&msk, (char *)IDB, sizeof(IDB), klen, kbuf, C);

    PERFORMANCE_TEST_NEW("RELIC SM9_kem_decrypt ",sm9_kem_decrypt(&enc_key,(char *)IDB, sizeof(IDB),C,klen,kbuf) );		
	//sm9_kem_decrypt(&enc_key,(char *)IDB, sizeof(IDB),C,klen,kbuf);

	printf("%s() ok\n", __FUNCTION__);
	
	ep_free(msk.Ppube);
	bn_free(msk.ke);
	ep_free(enc_key.Ppube);
	ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);

	return 1;
err:
	ep_free(msk.Ppube);
	bn_free(msk.ke);
	ep_free(enc_key.Ppube);
	ep2_free(enc_key.de);

    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}


int speedtest_sm9_enc_dec() {
	SM9_ENC_MASTER_KEY msk;
	SM9_ENC_KEY enc_key;

    //enc_master_key_init(&msk);
    //enc_user_key_init(&enc_key);

	ep_null(enc_key.Ppube);
	ep_new(enc_key.Ppube);
	ep2_null(enc_key.de);
	ep2_new(enc_key.de);

    uint8_t out[1000] = {0};
	size_t outlen = 0;
	int j = 1;

	//Chinese IBE standard
	uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x45, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
	uint8_t dec[20] = {0};
	size_t declen = 20;

	//Bob
	uint8_t IDB[3] = {0x42, 0x6F, 0x62};

	enc_master_key_init(&msk);

	if (sm9_enc_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &enc_key) < 0) goto err; ++j;
	
	//if (sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen) < 0) goto err; ++j;
	PERFORMANCE_TEST_NEW("RELIC SM9_encrypt ",sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen) );
	//format_bytes(stdout, 0, 0, "ciphertext", out, outlen);
	PERFORMANCE_TEST_NEW("RELIC SM9_decrypt ",sm9_decrypt(&enc_key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen) );	
	// if (sm9_decrypt(&enc_key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen) < 0) goto err; ++j;
	if (memcmp(data, dec, sizeof(data)) != 0) goto err; ++j;
	//format_bytes(stdout, 0, 0, "plaintext", dec, declen);
	printf("%s() ok\n", __FUNCTION__);
	
	ep_free(msk.Ppube);
	bn_free(msk.ke);
	ep_free(enc_key.Ppube);
	ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);

	return 1;
err:
	ep_free(msk.Ppube);
	bn_free(msk.ke);
	ep_free(enc_key.Ppube);
	ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}