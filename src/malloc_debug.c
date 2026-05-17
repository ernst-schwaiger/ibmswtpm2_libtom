#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>

#include "malloc_debug.h"

static uint32_t malloc_counter;
static uint32_t malloc_size;
static uint32_t calloc_counter;
static uint32_t calloc_size;
static uint32_t realloc_counter;
static uint32_t realloc_size;
static uint32_t free_counter;
static uint32_t free_size;


void *MP_MALLOC(size_t size)
{
    ++malloc_counter;
    malloc_size += size;
    return malloc(size);
}

void *MP_REALLOC(void *mem, size_t oldsize, size_t newsize)
{
    ++realloc_counter;
    assert(oldsize < newsize);
    realloc_size += (newsize - oldsize);
    return realloc(mem, newsize);
}

void *MP_CALLOC(size_t nmemb, size_t size)
{
    ++calloc_counter;
    calloc_size += size;
    return calloc(nmemb, size);
}

void MP_FREE(void *mem, size_t size)
{
    ++free_counter;
    free_size += size;
    free(mem);
}

void printMallocInfo(void)
{
    printf("Malloc counter: %d, num_bytes: %d\r\n", malloc_counter, malloc_size);
    printf("Realloc counter: %d, num_bytes: %d\r\n", realloc_counter, realloc_size);
    printf("Calloc counter: %d, num_bytes: %d\r\n", calloc_counter, calloc_size);
    printf("Free counter: %d, num_bytes: %d\r\n", free_counter, free_size);
}
