#include <execinfo.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * This is an POSIX SIGNAL STRC+C
 */
void exitFunction(int x)
{
	printf("By By...\r\n");
	exit(0);
}

/*
 * This is an POSIX segmentation fault SIGNAL
 * Use then :
 *  addr2line --exe=programmname 0x401373 <- The adress depends on output from the stack trace
 *  Then you your are able to see where you have done the memory pig.
 */
void segsevFunction(int sig)
{

    void *array[1000];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 1000);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);

}

int init_signal_handling(unsigned int sig)
{

	/*
	 * This signal is STRG-C on console
	 */
	signal(SIGINT, exitFunction);

	/*
	 * This signal is for segmentation fault
	 */
	signal(SIGSEGV, segsevFunction);
	signal(SIGIO, segsevFunction);

	return 0;

}

int absturz(void)
{
	printf("Diese Funktion generiert ein Absturz\r\n");

	for (int x = 0; x <= 0xFFFFFF; x++)
	{
		char *p = NULL;
		printf("Absturz");
		*p = x;
	}

	return 0;
}
