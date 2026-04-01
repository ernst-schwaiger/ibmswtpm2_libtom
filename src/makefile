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

# DEBUG, RELEASE, COVERAGE
BUILD_MODE ?= DEBUG

CC = /usr/bin/gcc

CCFLAGS_WARNINGS =	-Wall 	\
	-Wmissing-declarations 	\
	-Wmissing-prototypes 	\
	-Wnested-externs 		\
	-Werror -Wsign-compare 	\
	-Wno-deprecated-declarations

CCFLAGS_SYMBOLS = 	\
	-DTPM_POSIX		\
	-D_POSIX_		\
	-DTPM_NUVOTON

# add this line for big endian platforms
#	-DBIG_ENDIAN_TPM=YES

CCFLAGS_INCLUDE =	\
	-I$(HOME)/projects/PortSwTpm2LibTom/libtommath \
	-I$(HOME)/projects/PortSwTpm2LibTom/libtomcrypt/src/headers

LNFLAGS_LIBS = 	\
	-lpthread	\
	-ltomcrypt	\
	-ltommath	\
	-lrt

ifeq ($(BUILD_MODE), DEBUG)
# DEBUG info, ASAN turned on, optimizations turned off
	CCFLAGS_OPT = -fsanitize=address -ggdb3 -O0 
	CCFLAGS_SYMBOLS += 	-DDEBUG_TPM
	LNFLAGS_OPTS = -fsanitize=address

	LNFLAGS_INCLUDE = 	\
		-L$(HOME)/projects/PortSwTpm2LibTom/libtommath/buildasan \
		-L$(HOME)/projects/PortSwTpm2LibTom/libtomcrypt/buildasan		
else ifeq ($(BUILD_MODE), RELEASE)
# DEBUG info, ASAN turned off, optimzations turned on
	CCFLAGS_OPT = 	\
		-O2

	LNFLAGS_INCLUDE = 	\
	-L$(HOME)/projects/PortSwTpm2LibTom/libtommath/buildrelease \
	-L$(HOME)/projects/PortSwTpm2LibTom/libtomcrypt/buildrelease
else ifeq ($(BUILD_MODE), COVERAGE)
# Coverage build
	CCFLAGS_OPT = -ggdb3 -O0 --coverage
	CCFLAGS_SYMBOLS += 	-DCOVERAGE
	LNFLAGS_OPTS = --coverage

	LNFLAGS_INCLUDE = 	\
		-L$(HOME)/projects/PortSwTpm2LibTom/libtommath/build \
		-L$(HOME)/projects/PortSwTpm2LibTom/libtomcrypt/build		

else
    $(error "Unknown build configuration: $(BUILD_MODE)")
endif

CCFLAGS = $(CCFLAGS_WARNINGS) -c $(CCFLAGS_SYMBOLS) $(CFLAGS) $(CCFLAGS_OPT) $(CCFLAGS_INCLUDE)
LNFLAGS = $(LNFLAGS_LIBS) $(LDFLAGS) $(LNFLAGS_OPTS) $(LNFLAGS_INCLUDE)

all:	tpm_server

# contributed code, not tested
install:	tpm_server
		install -d $(DESTDIR)/usr/bin
		install -t $(DESTDIR)/usr/bin $<

include makefile-common

OBJFILES += TcpServerPosix.o

TcpServerPosix.o	: $(HEADERS)

.PHONY:		clean
.PRECIOUS:	%.o

tpm_server:	$(OBJFILES)
	$(CC) $(OBJFILES) $(LNFLAGS) -o tpm_server

clean:		
	rm -rf *.o tpm_server *~ *.gcda *.gcno test.tracefile test.lcov coverage

COV_FILES=$(patsubst %.o,%.c,$(OBJFILES))

test.lcov:
	$(info "GCDA files: $(GCDA_FILES)")
	$(info "COV files: $(COV_FILES)")
	lcov --directory . --capture --rc branch_coverage=1 -o test.tracefile
	lcov --ignore-errors unused -o test.lcov --rc branch_coverage=1 -e test.tracefile $(COV_FILES)
	genhtml --rc genhtml_hi_limit=0 --rc genhtml_med_limit=0 test.lcov -o ./coverage --branch-coverage

%.o:		%.c
		$(CC) $(CCFLAGS) $< -o $@
