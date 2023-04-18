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

/***************性能测试代码*******************/
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

static int run = 0;
// static int usertime = 1;

#define TM_START        0
#define TM_STOP         1

#define START        0
#define STOP         1

static void alarmed(int sig)
{
    signal(SIGALRM, alarmed); 
    run = 0;
}

double app_tminterval(int stop)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    // if (usertime)
    //     now = rus.tms_utime;

    if (stop == TM_START) {
        tmstart = now;
    } else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }
    return ret;
}

// s为STOP时，返回间隔时间
static double Time_F(int s)
{
    double ret = app_tminterval(s);  // 返回
    if (s == STOP)
        alarm(0);  // 停止闹钟
    return ret;
}

// GmSSL'sfp12_mul,Relic'sfp12_mul_t和fp12_sparse性能比较
void performance_compare_num(const fp12_t a,const fp12_t b){
	fp12_t r;
    int count;
    int sec = 1;
    double d = 0.0;

    // 注册计时器
    signal(SIGALRM, alarmed); 

	// fp12_mul_t1
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_t1(r, a, b);
    }
    d = Time_F(STOP);
    printf("GmSSL's fp12_mul: run %d times in %.2fs\n", count, d);

    // fp12_mul_t
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_t(r, a, b);
    }
    d = Time_F(STOP);
    printf("Relic's fp12_mul: run %d times in %.2fs\n", count, d);

    // fp12_mul_sparse
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_sparse(r, a, b);
    }
    d = Time_F(STOP);
    printf("fp12_mul_sparse : run %d times in %.2fs\n", count, d);

	// fp12_mul_sparse_t
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_sparse_t(r, a, b);
    }
    d = Time_F(STOP);
    printf("fp12_mul_sparse_t : run %d times in %.2fs\n", count, d);

    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_dxs_t(r, a, b);
    }
    d = Time_F(STOP);
    printf("fp12_mul_dxs_t : run %d times in %.2fs\n", count, d);

    return ;

}

// GmSSL's fp12_mul,Relic's fp12_mul_t和fp12_sparse2性能比较
static void performance_compare_den(const fp12_t a,const fp12_t b){
	fp12_t r;
    int count;
    int sec = 1;
    double d = 0.0;

    // 注册计时器
    signal(SIGALRM, alarmed);

	
    // fp12_mul_t1
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_t1(r, a, b);
    }
    d = Time_F(STOP);
    printf("GmSSL's fp12_mul: run %d times in %.2fs\n", count, d);

    // fp12_mul_t
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_t(r, a, b);
    }
    d = Time_F(STOP);
    printf("Relic's fp12_mul: run %d times in %.2fs\n", count, d);

    // fp12_mul_sparse2
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        fp12_mul_sparse2(r, a, b);
    }
    d = Time_F(STOP);
    printf("fp12_mul_sparse2: run %d times in %.2fs\n", count, d);

    return ;
}
/***************性能测试代码 end *******************/
void sm9_pairing_omp_t(fp12_t r_arr[], const ep2_t Q_arr[], const ep_t P_arr[], const size_t arr_size, const size_t threads_num){
	// omp_set_num_threads(threads_num);
	// sm9_init();

	#pragma omp parallel for num_threads(threads_num)
	for (size_t i = 0; i < arr_size*2; i++)
	{
		// sm9_pairing(r_arr[0], Q_arr[0], P_arr[0]);
		g1_t g1;
		ep2_t Ppub;
		fp12_t r;

		g1_null(g1);
		g1_new(g1);
		ep2_null(Ppub);
		ep2_new(Ppub);
		fp12_null(r);
		fp12_new(r);

		g1_get_gen(g1);

		char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
		char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
		char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
		char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
		char z0[] = "1";
		char z1[] = "0";

		fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
		fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
		fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
		fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
		fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
		fp_read_str(Ppub->z[1], z1, strlen(z1), 16);
		
		sm9_pairing(r, Ppub, g1);

		sm9_clean();
		g1_free(g1);
		ep2_free(Ppub);
		fp12_free(r);
		// sm9_pairing_test();
	}
}

void sm9_pairing_test(){
	g1_t g1;
	ep2_t Ppub;
	fp12_t r;

	g1_null(g1);
	g1_new(g1);
	ep2_null(Ppub);
	ep2_new(Ppub);
	fp12_null(r);
	fp12_new(r);

	g1_get_gen(g1);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);
	
	sm9_init();
	
	sm9_pairing(r, Ppub, g1);
	
	sm9_clean();
	g1_free(g1);
	ep2_free(Ppub);
	fp12_free(r);
}

void test_sm9_pairing(int threads_num){
	g1_t g1;
	ep2_t Ppub;
	fp12_t r;

	g1_null(g1);
	g1_new(g1);
	g1_get_gen(g1);

	ep2_null(Ppub);
	ep2_new(Ppub);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

	fp12_null(r);
	fp12_new(r);

	sm9_init();

#if 0
	// 测试正确性
	sm9_pairing_fastest(r, Ppub, g1);
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("out: r\n");
	fp12_print(r);
	
	// pp_map_tatep_k12(r, g1, Ppub);
	// printf("tatep: r\n");
	// fp12_print(r);

	// pp_map_weilp_k12(r, g1, Ppub);
	// printf("weilp: r\n");
	// fp12_print(r);

	// pp_map_oatep_k12(r, g1, Ppub);
	// printf("oatep: r\n");
	// fp12_print(r);
#endif

#if 0
	PERFORMANCE_TEST_NEW("pairing", sm9_pairing(r, Ppub, g1));
	PERFORMANCE_TEST_NEW("pp_map_tatep_k12(r, g1, Ppub)", pp_map_tatep_k12(r, g1, Ppub));
	PERFORMANCE_TEST_NEW("pp_map_weilp_k12(r, g1, Ppub)", pp_map_weilp_k12(r, g1, Ppub));
	PERFORMANCE_TEST_NEW("pp_map_oatep_k12(r, g1, Ppub)", pp_map_oatep_k12(r, g1, Ppub));
#endif
	
#if 0
	//test functions
	//printf("raw :\n");
	//sm9_pairing_function_test(r, Ppub, g1);
	sm9_pairing_steps_test(r, Ppub, g1);
	printf("updated :\n");
	sm9_pairing_fastest_function_test(r, Ppub, g1);
	//sm9_pairing_fastest_step_test(r, Ppub, g1);
	//sm9_TEST(r,Ppub,g1);	
	// sm9_pairing_function_test(r, Ppub, g1);
	// sm9_pairing_steps_test(r, Ppub, g1);
	// sm9_TEST(r,Ppub,g1);
	//sm9_pairing_fast_step_test(r, Ppub, g1);

	//sm9_pairing_fastest_step_test(r, Ppub, g1);
#endif

#if 0
	// 测试性能
	// PERFORMANCE_TEST("pairing", sm9_pairing(r, Ppub, g1), 1000);
	pthread_attr_t attr; // 定义线程属性

	size_t count=1000;
	fp12_t r_arr[count];
	g1_t g1_arr[count];
	ep2_t Ppub_arr[count];

	for (size_t i = 0; i < count; i++)
	{
		fp12_null(r_arr[i]);
		fp12_new(r_arr[i]);
		g1_null(g1_arr[i]);
		g1_new(g1_arr[i]);
		ep2_null(Ppub_arr[i]);
		ep2_new(Ppub_arr[i]);
		g1_copy(g1_arr[i], g1);
		ep2_copy(Ppub_arr[i], Ppub);
	}
	
	double begin, end;
	// int threads_num = 5;
	// omp_set_num_threads(threads_num);
	begin = omp_get_wtime();
	sm9_pairing_omp_t(r_arr, Ppub_arr, g1_arr, count, threads_num);
	end = omp_get_wtime();
	printf("run %d times, threads num: %d, total time: %f s, one time: %f s\n", \
			count, threads_num, 1.0*(end-begin), 1.0*(end-begin)/count);

	
	// #pragma omp parallel	
	// {
	// 	int id = omp_get_thread_num();
	// 	printf("id=%d\n", id);
	// 	for (size_t i = 0; i < count; i+=threads_num)
	// 	{
	// 		sm9_pairing(r_arr[i+id], Ppub_arr[i+id], g1_arr[i+id]);
	// 	}
	// }

	// 清理空间
	for (size_t i = 0; i < count; i++)
	{
		fp12_free(r_arr[i]);
		g1_free(g1_arr[i]);
		ep2_free(Ppub_arr[i]);
	}
#endif


	sm9_clean();
	g1_free(g1);
	ep2_free(Ppub);
	fp12_free(r);
	return 1;
}


void test_miller(){
	g1_t g1;
	ep2_t Ppub;
	fp12_t r;

	g1_null(g1);
	g1_new(g1);
	g1_get_gen(g1);

	ep2_null(Ppub);
	ep2_new(Ppub);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

	fp12_null(r);
	fp12_new(r);

	sm9_init();


#if 1
	// 测试正确性
	printf("Fast sm9 pairing is running.\n");
	sm9_pairing_fast(r, Ppub, g1);
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("out: r\n");
	fp12_print(r);
#endif
#if 0
/* 性能对比 */
	test_sm9_pairing_fast(r,Ppub,g1);
	test_sm9_pairing(r,Ppub,g1);
#endif

}

void test_ep_add(){
	ep2_t R,P,Q;

	ep2_null(R);
	ep2_new(R);	
	ep2_null(Q);
	ep2_new(Q);
	ep2_null(P);
	ep2_new(P);

	ep2_rand(P);
	ep2_rand(Q);
	fp2_set_dig(Q->z,1);

    int count;
    int sec = 1;
    double d = 0.0;

    // 注册计时器
    signal(SIGALRM, alarmed); 

	
    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        ep2_add_full(R,P,Q);
    }
    d = Time_F(STOP);
    printf("GmSSL's ep2 add: run %d times in %.2fs\n", count, d);

    alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        ep2_add_t(R,P,Q);
    }
    d = Time_F(STOP);
    printf("special ep2 add: run %d times in %.2fs\n", count, d);

	alarm(sec);
    run = 1;
    Time_F(START);
    for (count = 0; run && count < 0x7fffffff; count++)
    {
        ep2_add(R,P,Q);
    }
    d = Time_F(STOP);
    printf("Relic's ep2 add: run %d times in %.2fs\n", count, d);
	
    return ;
}

void test_a_lot(){
	g1_t g1;
	ep2_t Ppub;
	fp12_t r,t,f_num,g_num,f_den,g_den,temp;
	bn_t k;
	bn_null(k);
	bn_new(k);
	g1_null(g1);
	g1_new(g1);
	g1_get_gen(g1);


	ep2_null(Ppub);
	ep2_new(Ppub);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

	fp12_null(r);
	fp12_new(r);
	fp12_null(f_num);
	fp12_new(f_num);	
	fp12_null(g_num);
	fp12_new(g_num);
	fp12_null(f_den);
	fp12_new(f_den);	
	fp12_null(g_den);
	fp12_new(g_den);	
	fp12_null(t);
	fp12_new(t);
	fp12_null(temp);
	fp12_new(temp);

	sm9_init();

#if 0
	// 非退化性测试1
	printf("TEST\n");
	ep_rand(g1);
	ep2_rand(Ppub);
	sm9_init();
	
	sm9_pairing(r, Ppub, g1);
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("out: r\n");
	fp12_print(r);
#endif
#if 0
	// 非退化性测试2
	printf("TEST\n");
	ep_rand(g1);
	ep2_set_infty(Ppub);
	sm9_init();
	
	sm9_pairing(r, Ppub, g1);
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("out: r\n");
	fp12_print(r);
#endif
#if 0
	// 非退化性测试3
	printf("TEST\n");
	ep_set_infty(g1);
	ep2_rand(Ppub);
	sm9_init();
	
	sm9_pairing(r, Ppub, g1);
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("out: r\n");
	fp12_print(r);
#endif
#if 0
	// 双线性测试1
	printf("TEST\n");

	g1_t gtemp;
	ep2_t Ptemp;
	g1_null(gtemp);
	g1_get_gen(gtemp);
	ep2_null(Ptemp);
	ep2_new(Ptemp);

	bn_rand(k,RLC_POS,100);
	ep_rand(g1);
	ep2_rand(Ppub);

	ep_mul_basic(gtemp,g1,k);
	ep2_mul_basic(Ptemp,Ppub,k);

	sm9_init();
	
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("in: Ptemp\n");
	ep2_print(Ptemp);
	printf("in: gtemp\n");
	ep_print(gtemp);
	printf("out: r1\n");
	sm9_pairing(r, Ppub, gtemp);
	fp12_print(r);

	
	sm9_pairing(r, Ptemp, g1);
	printf("out: r2\n");
	fp12_print(r);

	g1_free(gtemp);
	ep2_free(Ptemp);
#endif
#if 0
	// 双线性测试2
	printf("TEST\n");

	g1_t gtemp;
	g1_null(gtemp);
	g1_get_gen(gtemp);

	bn_rand(k,RLC_POS,100);
	ep_rand(g1);
	ep2_rand(Ppub);

	ep_mul_basic(gtemp,g1,k);

	sm9_init();
	
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("in: gtemp\n");
	ep_print(gtemp);
	printf("out: r1\n");
	sm9_pairing(r, Ppub, gtemp);
	fp12_print(r);
	
	sm9_pairing(r, Ppub, g1);
	printf("out: r2\n");
	fp12_print(r);
	fp12_pow_t(r,r,k);
	printf("out: r2^k\n");
	fp12_print(r);

	g1_free(gtemp);
#endif
#if 0
	// 双线性测试3
	printf("TEST\n");

	ep2_t Ptemp;
	ep2_null(Ptemp);
	ep2_new(Ptemp);

	bn_rand(k,RLC_POS,255);
	ep2_rand(Ppub);
	ep2_mul_basic(Ptemp,Ppub,k);

	sm9_init();
	
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("in: Ptemp\n");
	ep2_print(Ptemp);
	printf("out: r1\n");
	sm9_pairing(r, Ptemp, g1);
	fp12_print(r);

	sm9_pairing(r, Ppub, g1);
	printf("out: r2\n");
	fp12_print(r);
	fp12_pow_t(r,r,k);
	printf("out: r2^k\n");
	fp12_print(r);

	ep2_free(Ptemp);
#endif
#if 0
	// 双线性测试4
	printf("TEST\n");
	bn_t k2;
	bn_null(k2);
	bn_new(k2);

	g1_t gtemp;
	ep2_t Ptemp;
	g1_null(gtemp);
	g1_get_gen(gtemp);
	ep2_null(Ptemp);
	ep2_new(Ptemp);

	bn_rand(k,RLC_POS,255);
	bn_rand(k2,RLC_POS,255);
	ep_rand(g1);
	ep2_rand(Ppub);

	ep_mul_basic(gtemp,g1,k);
	ep2_mul_basic(Ptemp,Ppub,k2);

	sm9_init();
	
	printf("in: Ppub\n");
	ep2_print(Ppub);
	printf("in: g1\n");
	ep_print(g1);
	printf("in: Ptemp\n");
	ep2_print(Ptemp);
	printf("in: gtemp\n");
	ep_print(gtemp);
	printf("out: r1\n");
	sm9_pairing(r, Ptemp, gtemp);
	fp12_print(r);

	
	sm9_pairing(r, Ppub, g1);
	printf("out: r2\n");
	fp12_print(r);
	fp12_pow_t(r,r,k);
	fp12_pow_t(r,r,k2);
	printf("out: r2^{k1*k2}\n");
	fp12_print(r);

	g1_free(gtemp);
	ep2_free(Ptemp);
	bn_free(k2);
#endif
#if 0
	/* GmSSL、relic乘法正确性测试与性能测试*/
#endif
#if 1
	/* 稀疏乘法正确性测试与性能测试 ，分开测有点麻烦，所以一起测了*/
	fp12_set_dig(f_num, 1);
	fp12_set_dig(f_den, 1);
	fp12_sqr_t(f_num, f_num);
	fp12_sqr_t(f_den, f_den);

	sm9_eval_g_tangent(g_num, g_den, Ppub, g1);

	printf("--------Mul Sparse Correctness Test--------\n");
	fp12_mul_t1(temp,f_num,g_num);
	fp12_mul_t(r, f_num, g_num);
	fp12_mul_dxs(t, f_num, g_num);  
	
	if( fp12_cmp(temp,r) == 0 && fp12_cmp(r, t) == 0 ){
		printf("Mul Spares equa\n");
	}else{
		printf("Mul Spares1 no equa\n");
	}

	fp12_mul_t1(temp,f_den,g_den);
	fp12_mul_t(r, f_den, g_den);
	fp12_mul_sparse2(t, f_den, g_den);
	if( fp12_cmp(temp,r) == 0 && fp12_cmp(r, t) == 0 ){
		printf("Mul Spares2 equa\n");
	}else{
		printf("Mul Spares2 no equa\n");
	}
	printf("--------Mul Sparse Correctness Test END--------\n\n");

	printf("--------Mul Sparse Profromence Test--------\n");
	performance_compare_num(f_num, g_num);
	printf("\n");
	performance_compare_den(f_den, g_den);
	printf("--------Mul Sparse Profromence Test END--------\n\n");
#endif

	sm9_clean();
	g1_free(g1);
	ep2_free(Ppub);
	fp12_free(r);
	fp12_free(t);
	fp12_free(f_num);
	fp12_free(g_num);
	fp12_free(f_den);
	fp12_free(g_den);
	fp12_free(temp);
	bn_free(k);

	return;
}

void test()
{
	for (int i = 0; i < 80000; i++)
	{

	}
}
 
int test_main()
{
	float startTime = omp_get_wtime();
 
	//指定两个线程
#pragma omp parallel for num_threads(2)
	for (int i = 0; i < 80000; i++)
	{
		test();
	}
	float endTime = omp_get_wtime();
	printf("指定 2 个线程，执行时间: %f\n", endTime - startTime);
	startTime = endTime;
 
	//指定4个线程
#pragma omp parallel for num_threads(4)
	for (int i = 0; i < 80000; i++)
	{
		test();
	}
	endTime = omp_get_wtime();
	printf("指定 4 个线程，执行时间: %f\n", endTime - startTime);
	startTime = endTime;
 
	//指定8个线程  
#pragma omp parallel for num_threads(8)
	for (int i = 0; i < 80000; i++)
	{
		test();
	}
	endTime = omp_get_wtime();
	printf("指定 8 个线程，执行时间: %f\n", endTime - startTime);
	startTime = endTime;
 
	//指定12个线程
#pragma omp parallel for num_threads(12)
	for (int i = 0; i < 80000; i++)
	{
		test();
	}
	endTime = omp_get_wtime();
	printf("指定 12 个线程，执行时间: %f\n", endTime - startTime);
	startTime = endTime;
 
	//不使用OpenMP
	for (int i = 0; i < 80000; i++)
	{
		test();
	}
	endTime = omp_get_wtime();
	printf("不使用OpenMP多线程，执行时间: %f\n", endTime - startTime);
	startTime = endTime;

	return 0;
 
}

int str2int(char *str){
	int ret = 0;
	int base = 10;
	for (size_t i = 0; str[i]; i++)
	{
		if(i)
			ret *= base;
		ret += (str[i]-'0');
	}
	return ret;
}

void test_other_pairing(){
	g1_t g1;
	ep2_t Ppub;
	fp12_t r;

	g1_null(g1);
	g1_new(g1);
	g1_get_gen(g1);

	ep2_null(Ppub);
	ep2_new(Ppub);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

	fp12_null(r);
	fp12_new(r);

	sm9_init();

	sm9_clean();
	g1_free(g1);
	ep2_free(Ppub);
	fp12_free(r);

#if 0
	size_t count=1000;
	fp12_t r_arr[count];
	g1_t g1_arr[count];
	ep2_t Ppub_arr[count];

	for (size_t i = 0; i < count; i++)
	{
		fp12_null(r_arr[i]);
		fp12_new(r_arr[i]);
		g1_null(g1_arr[i]);
		g1_new(g1_arr[i]);
		ep2_null(Ppub_arr[i]);
		ep2_new(Ppub_arr[i]);
		g1_copy(g1_arr[i], g1);z
		ep2_copy(Ppub_arr[i], Ppub);
	}
	
	double begin, end;
	begin = omp_get_wtime();
	for(size_t i = 0; i < count;i++){
		pp_map_weilp_k12(r_arr[i],g1_arr[i],Ppub_arr[i]);
	}
	end = omp_get_wtime();
	printf("weil pairing run %d times, total time: %f s, one time: %f s\n", \
			count, 1.0*(end-begin), 1.0*(end-begin)/count);

	
	begin = omp_get_wtime();
	for(size_t i = 0; i < count;i++){
		pp_map_oatep_k12(r_arr[i],g1_arr[i],Ppub_arr[i]);
	}
	end = omp_get_wtime();
	printf("oate pairing run %d times, total time: %f s, one time: %f s\n", \
			count, 1.0*(end-begin), 1.0*(end-begin)/count);


	
	begin = omp_get_wtime();
	for(size_t i = 0; i < count;i++){
		pp_map_tatep_k12(r_arr[i],g1_arr[i],Ppub_arr[i]);
	}
	end = omp_get_wtime();
	printf("tate pairing run %d times, total time: %f s, one time: %f s\n", \
			count, 1.0*(end-begin), 1.0*(end-begin)/count);

	for (size_t i = 0; i < count; i++)
	{
		fp12_free(r_arr[i]);
		g1_free(g1_arr[i]);
		ep2_free(Ppub_arr[i]);
	}
#endif
	sm9_clean();
	g1_free(g1);
	ep2_free(Ppub);
	fp12_free(r);
	return 1;
}

void test_other_pairing_new(){
	g1_t g1;
	ep2_t Ppub;
	fp12_t r;

	g1_null(g1);
	g1_new(g1);
	g1_get_gen(g1);

	ep2_null(Ppub);
	ep2_new(Ppub);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

	fp12_null(r);
	fp12_new(r);

	sm9_init();


#if 1
	PERFORMANCE_TEST_NEW("pairing_gmssl", sm9_pairing(r, Ppub, g1));
	//PERFORMANCE_TEST_NEW("pairing_fast", sm9_pairing_fast(r, Ppub, g1));
	//PERFORMANCE_TEST_NEW("pairing_faster", sm9_pairing_faster(r, Ppub, g1));
	PERFORMANCE_TEST_NEW("pairing_fastest", sm9_pairing_fastest(r, Ppub, g1));
	//fp12_print(r);
	//PERFORMANCE_TEST_NEW("pairing_fastest2", sm9_pairing_fastest2(r, Ppub, g1));

	PERFORMANCE_TEST_NEW("pp_map_tatep_k12(r, g1, Ppub)", pp_map_tatep_k12(r, g1, Ppub));
	PERFORMANCE_TEST_NEW("pp_map_weilp_k12(r, g1, Ppub)", pp_map_weilp_k12(r, g1, Ppub));
	PERFORMANCE_TEST_NEW("pp_map_oatep_k12(r, g1, Ppub)", pp_map_oatep_k12(r, g1, Ppub));
	
#endif

#if 0
	// sm9_pairing(r, Ppub, g1);
	sm9_pairing_fast(r, Ppub, g1);
	pp_map_tatep_k12(r, g1, Ppub);
	// pp_map_weilp_k12(r, g1, Ppub);
	// pp_map_oatep_k12(r, g1, Ppub);
#endif
	sm9_clean();
	g1_free(g1);
	ep2_free(Ppub);
	fp12_free(r);
	return 1;
}


int main(int argc, char *argv[]) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (pc_param_set_any() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	// pc_param_print();
	// test_main();

	// 单线程测试
	//test_sm9_pairing(1);

	// 多线程测试
#if 0
	if(argc == 1){
		test_sm9_pairing(1);
		test_sm9_pairing(2);
		test_sm9_pairing(4);
		test_sm9_pairing(8);
		test_sm9_pairing(12);
		test_sm9_pairing(16);
	}else{
		int num = str2int(argv[1]);
		test_sm9_pairing(num);
	}
#endif
	// test_other_pairing();
	//test_other_pairing_new();
	test_a_lot();
	// test_miller();
	//test_ep_add();
	//test_sm9_sign_and_verify();
	core_clean();

	return 0;
}
