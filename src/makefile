#################################################################################
#										#
#			Linux gcc TPM2 Makefile					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2019					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

# Debug, Release, Coverage, Flamegraph
BUILD_MODE ?= Debug
IS_32BIT   ?= False

ifeq ($(IS_32BIT), True)
	CC = arm-linux-gnueabihf-gcc
	PWD=$(shell pwd)
	CMAKE_TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=$(PWD)/toolchain-armhf.cmake"
else
	CC = gcc
	CMAKE_TOOLCHAIN_FILE=
endif

PROJECT_FOLDER=./..

CCFLAGS_WARNINGS =	-Wall 	\
	-Wmissing-declarations 	\
	-Wmissing-prototypes 	\
	-Wnested-externs 		\
	-Werror -Wsign-compare 	\
	-Wno-deprecated-declarations

CCFLAGS_SYMBOLS = 	\
	-DTPM_POSIX		\
	-D_POSIX_		\
	-DTPM_NUVOTON	\
	-DLTM_TPM

# add this line for big endian platforms
#	-DBIG_ENDIAN_TPM=YES

CCFLAGS_INCLUDE =	\
	-Ilibtommath \
	-Ilibtomcrypt/src/headers

LNFLAGS_LIBS = 	\
	-lpthread	\
	-ltomcrypt	\
	-ltommath	\
	-lrt

ifeq ($(BUILD_MODE), Debug)
# DEBUG info, ASAN turned on, optimizations turned off
	CCFLAGS_OPT = -fsanitize=address -g -O0 
	CCFLAGS_SYMBOLS += 	-DDEBUG_TPM
	LNFLAGS_OPTS = -fsanitize=address

	LNFLAGS_INCLUDE = 	\
		-Llibtommath/buildasan \
		-Llibtomcrypt/buildasan		
else ifeq ($(BUILD_MODE), Release)
# DEBUG info, ASAN turned off, optimzations turned on
	CCFLAGS_OPT = 	\
		-O2

	LNFLAGS_INCLUDE = 	\
	-L$(PROJECT_FOLDER)/../libtommath/buildrelease \
	-L$(PROJECT_FOLDER)/../libtomcrypt/buildrelease
else ifeq ($(BUILD_MODE), Coverage)
# Coverage build
	CCFLAGS_OPT = -ggdb3 -O0 --coverage
	CCFLAGS_SYMBOLS += 	-DCOVERAGE
	LNFLAGS_OPTS = --coverage

	LNFLAGS_INCLUDE = 	\
		-L$(PROJECT_FOLDER)/../libtommath/buildcov \
		-L$(PROJECT_FOLDER)/../libtomcrypt/buildcov		
else ifeq ($(BUILD_MODE), Flamegraph)
	CCFLAGS_OPT = -g -O2 -fno-omit-frame-pointer
	LNFLAGS_OPTS = -fno-omit-frame-pointer

	LNFLAGS_INCLUDE = 	\
		-L$(PROJECT_FOLDER)/../libtommath/buildflame \
		-L$(PROJECT_FOLDER)/../libtomcrypt/buildflame		
else
    $(error "Unknown build configuration: $(BUILD_MODE)")
endif

LNFLAGS_INCLUDE = 	\
	-Llibtommath/$(BUILD_MODE) \
	-Llibtomcrypt/$(BUILD_MODE)		

CCFLAGS = $(CCFLAGS_WARNINGS) -c $(CCFLAGS_SYMBOLS) $(CFLAGS) $(CCFLAGS_OPT) $(CCFLAGS_INCLUDE)
LNFLAGS = $(LNFLAGS_LIBS) $(LNFLAGS_OPTS) $(LNFLAGS_INCLUDE)

# LibTomCrypt and LibTomMath do not publish releases, so we have to stick to fixed revisions
LIBTOMCRYPT_HASH = 63af5f6dc15a686ff2099676e0fd02550ec87659
LIBTOMMATH_HASH = 839ae9ea66718705fba2b5773d1bdfb2b457cea4

all:	tpm_server_$(BUILD_MODE)

# contributed code, not tested
install:	tpm_server
		install -d $(DESTDIR)/usr/bin
		install -t $(DESTDIR)/usr/bin $<

include makefile-common

OBJFILES += $(BUILD_MODE)/TcpServerPosix.o

$(BUILD_MODE)/TcpServerPosix.o	: $(HEADERS)

.PHONY:		clean
.PRECIOUS:	%.o

tpm_server_$(BUILD_MODE): $(OBJFILES) libtomcrypt/$(BUILD_MODE)/libtomcrypt.a libtommath/$(BUILD_MODE)/libtommath.a
	$(CC) $(OBJFILES) $(LNFLAGS) -o tpm_server_$(BUILD_MODE)

libtomcrypt/$(BUILD_MODE)/libtomcrypt.a: libtomcrypt libtommath/$(BUILD_MODE)/libtommath.a
	cmake -S libtomcrypt -B libtomcrypt/$(BUILD_MODE) $(CMAKE_TOOLCHAIN_FILE) \
		"-DCMAKE_C_FLAGS=$(CCFLAGS_WARNINGS) $(CCFLAGS_SYMBOLS) $(CFLAGS) $(CCFLAGS_OPT) -DLTM_TPM -DCMAKE_LINKER_FLAGS=$(LNFLAGS_OPTS)"
	cmake --build libtomcrypt/$(BUILD_MODE) -j

# checkout libtomcrypt, patch descriptor table (remove unused functions)
libtomcrypt:
	git clone --depth 1 https://github.com/libtom/libtomcrypt.git 
	cd libtomcrypt && git fetch --depth 1 origin $(LIBTOMCRYPT_HASH) && git checkout $(LIBTOMCRYPT_HASH)
	cp patch/libtomcrypt/tomcrypt_custom.h libtomcrypt/src/headers
	cp patch/libtomcrypt/ltm_desc.c libtomcrypt/src/math/
	cp patch/libtomcrypt/tweetnacl.c libtomcrypt/src/pk/ec25519

libtommath/$(BUILD_MODE)/libtommath.a: libtommath
	cmake -S libtommath -B libtommath/$(BUILD_MODE) $(CMAKE_TOOLCHAIN_FILE) \
		"-DCMAKE_C_FLAGS=$(CCFLAGS_WARNINGS) $(CCFLAGS_SYMBOLS) $(CFLAGS) $(CCFLAGS_OPT) -DLTM_TPM -DCMAKE_LINKER_FLAGS=$(LNFLAGS_OPTS)"
	cmake --build libtommath/$(BUILD_MODE) -j

# checkout libtomcrypt, patch class config files (remove unused functions)
libtommath:
	git clone --depth 1 https://github.com/libtom/libtommath.git
	cd libtommath && git fetch --depth 1 origin $(LIBTOMMATH_HASH) && git checkout $(LIBTOMMATH_HASH)
	cp patch/libtommath/tommath_class.h libtommath
	cp patch/libtommath/tommath_superclass.h libtommath

clean:		
	rm -rf tpm_server_$(BUILD_MODE) $(BUILD_MODE) libtomcrypt/$(BUILD_MODE) libtommath/$(BUILD_MODE) *~ *.gcda *.gcno test.tracefile test.lcov coverage

clobber:
	rm -rf tpm_server_* Debug Release Coverage Flamegraph libtomcrypt libtommath


COV_FILES_TPM=$(patsubst Coverage/%, %, $(patsubst %.o,%.c,$(OBJFILES)))
COV_FILES_LIBTOMCRYPT=$(shell find libtomcrypt -name "*.c")
COV_FILES_LIBTOMMATH=$(shell find libtommath -name "*.c")
COV_FILES=$(COV_FILES_TPM) $(COV_FILES_LIBTOMCRYPT) $(COV_FILES_LIBTOMMATH)

coverage:
	$(info "COV files: $(COV_FILES)")
	lcov --directory Coverage \
	    --directory libtommath/Coverage/CMakeFiles/libtommath.dir \
		--directory libtomcrypt/Coverage/CMakeFiles/libtomcrypt.dir/src \
		--capture --rc branch_coverage=1 -o test.tracefile
	lcov --ignore-errors unused -o test.lcov --rc branch_coverage=1 \
	    -e test.tracefile $(COV_FILES)
	genhtml --rc genhtml_hi_limit=0 --rc genhtml_med_limit=0 test.lcov \
		-o ./coverage --branch-coverage

PERF=$(shell which perf)
STACK_COLLAPSE=../../FlameGraph/stackcollapse-perf.pl
FLAMEGRAPH=../../FlameGraph/flamegraph.pl

flamegraph:
	sudo $(PERF) record -F 99 -p $(shell pidof tpm_server_Flamegraph) -g -- sleep 600
	sudo $(PERF) script >out.perf
	sudo chmod 666 out.perf
	$(STACK_COLLAPSE) out.perf > out.folded
	$(FLAMEGRAPH) out.folded > flamegraph.svg

	

$(BUILD_MODE)/%.o:		%.c libtomcrypt libtommath
	mkdir -p $(BUILD_MODE)
	$(CC) $(CCFLAGS) $< -o $@
