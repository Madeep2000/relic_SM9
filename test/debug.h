#pragma once
#ifndef DEBUG_H
#define DEBUG_H
#include <time.h>
#define SECOND_TEST 3
time_t begin_t, end_t;
size_t count_t;
double time_used;
size_t second_t;

#if 1
// 测试性能
#define PERFORMANCE_TEST(prestr, func, times) begin_t = clock();   \
	count_t = times;                                               \
	while (count_t)                                                \
	{                                                              \
		func;                                                      \
		count_t-=1;                                                \
	}                                                              \
	end_t = clock();                                               \
	printf("%s, run %d times, total time: %f s, one time: %f s\n", \
       	   prestr, times, 1.0*(end_t-begin_t)/CLOCKS_PER_SEC, 1.0*(end_t-begin_t)/CLOCKS_PER_SEC/times)
#else
	#define PERFORMANCE_TEST(prestr, func, times) {}
#endif

#endif

/***************性能测试代码*******************/
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

static int run_t = 0;
// static int usertime = 1;

#define TM_START        0
#define TM_STOP         1

#define START        0
#define STOP         1

static void alarmed_t(int sig)
{
    signal(SIGALRM, alarmed_t); 
    run_t = 0;
}

static double App_tminterval(int stop)
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
static double TIME_F(int s)
{
    double ret = App_tminterval(s);  // 返回
    if (s == STOP)
        alarm(0);  // 停止闹钟
    return ret;
}



// 测试性能
#define PERFORMANCE_TEST_NEW(prestr, func) begin_t = clock();                 \
	count_t = 0;                                                              \
	second_t =  SECOND_TEST;                                                  \
	time_used = 0.0;                                                          \
	signal(SIGALRM,alarmed_t);                                                \
	alarm(second_t);                                                          \
	run_t=1;                                                                  \
	TIME_F(START);                                                            \
    for(count_t=0;run_t&&count_t<0x7fffffff;count_t++){                       \
	    func;                                                                 \
    }                                                                         \
	time_used = TIME_F(STOP);                                                 \
	printf("%s run %d times in %.2fs, per second run %d times, each run takes %.2f ms\n", prestr, count_t, time_used, count_t/second_t, 1000.0/(count_t/second_t));

