CC=gcc
CCOPTS=-I/home/ernst/projects/wolfTPM -O2 -ggdb3 -Wall

all: benchmark

benchmark: benchmark.c
	$(CC) $(CCOPTS) benchmark.c -o benchmark -L/home/ernst/projects/wolfTPM/src/.libs -L/home/ernst/wolfssl_local/lib -lwolftpm -lwolfssl -lm -lpthread

clean:
	rm -f benchmark
