// OpenMPTest.cpp : 定义控制台应用程序的入口点。
//
 
// #include "stdafx.h"
#include "omp.h"
#include "stdio.h"
#include "time.h"
#include "unistd.h"

int y1 = 100;
int y2 = 100;
int y3 = 100;
int y4 = 100;
int y5 = 100;
int y6 = 100;

void sm9_pairing()
{	
	int x = 1;
	for (int i = 0; i < 20000; i++)
	{
		x = x*x*y1 + y2;
		x = x*y2*y1;
		x = x*x*y3 + y4;
		x = x*y5*y6;
		x = x*x*y4 + y2;
		x = x*y6*y1;
	}
}

void test_performance(size_t num){
	clock_t start, finish;

	float startTime = omp_get_wtime();
	//指定num个线程
	// 0x3ffffffff
	// 12800000000
	#pragma omp parallel for num_threads(num) private(y1,y2,y3,y4,y5,y6)
	for (unsigned long i = 0; i < 80000; ++i)
	{
		sm9_pairing();
	}
	float endTime = omp_get_wtime();
	printf("指定 %ld 个线程，执行时间: %f\n", num, endTime-startTime);
}

void test_clock(){
	clock_t start, finish;
	double duration;
	long i,j;
	start = clock();
	for( i=0;i<100;i++){
		for( j=0;j<1000000;j++){

		}
	}
	sleep(3);
	finish = clock();
	duration = (double)(finish- start) / CLOCKS_PER_SEC;
	printf( "Time to do %ld empty loops is ",i*j);
	printf( "%f seconds\n", duration);
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

int main(int argc, char *argv[])
{
	// test_clock();
	// printf("CLOCKS_PER_SEC = %d\n", CLOCKS_PER_SEC);
	if(argc == 1){
		test_performance(1);
		test_performance(2);
		test_performance(4);
		test_performance(8);
		test_performance(12);
		test_performance(16);
	}else{
		int num = str2int(argv[1]);
		test_performance(num);
	}
	return 0;
}