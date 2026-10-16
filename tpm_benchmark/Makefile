CC=gcc
CCOPTS=-I/home/ernst/projects/wolfTPM -O0 -ggdb3  

all: benchmark

benchmark: benchmark.c
	$(CC) $(CCOPTS) benchmark.c -o benchmark -L/home/ernst/projects/wolfTPM/src/.libs -L/home/ernst/wolfssl_local/lib -lwolftpm -lwolfssl -lm -lpthread

clean:
	rm -f benchmark

# gcc benchmark.c -o benchmark \
#   -I/home/ernst/projects/wolfTPM/ \
#   -L/home/ernst/projects/wolfTPM/src/.libs -lwolftpm \
#   -L/home/ernst/wolfssl_local/lib -lwolfssl \
#   -lm -lpthread