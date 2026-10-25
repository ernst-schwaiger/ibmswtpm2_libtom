#!/bin/bash

# paths to libraries that need to be loaded, e.g. wolfSSL
export LD_LIBRARY_PATH=/home/ernst/projects/wolfTPM/src/.libs:/usr/local/lib
# restrict execution of our benchmark to the last RASPI core
taskset -c 3 ./benchmark $1