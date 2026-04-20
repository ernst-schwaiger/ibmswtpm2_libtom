#!/bin/bash

# the revision used for testing the IBMTSS
IBMTSS_HASH=3a17ac01bea73d3568272d61b895a16a0bd85440
IBMTSS_FOLDER="$(realpath $(pwd)/../..)/ibmtss"

echo "Building ibmtss for UART in ${IBMTSS_FOLDER}..."

# Get the project, apply the patches
git clone --depth 1 https://github.com/kgoldman/ibmtss.git ${IBMTSS_FOLDER}
git -C ${IBMTSS_FOLDER} fetch --depth 1 origin $(LIBTOMCRYPT_HASH) 
git -C ${IBMTSS_FOLDER} checkout $(IBMTSS_HASH)
cp patchfiles/Makefile.am       ${IBMTSS_FOLDER}/utils
cp patchfiles/rootcerts.txt     ${IBMTSS_FOLDER}/utils/certificates
cp patchfiles/reg.sh            ${IBMTSS_FOLDER}/utils
cp patchfiles/inittpm.sh        ${IBMTSS_FOLDER}/utils/regtests
cp patchfiles/tssdev.c          ${IBMTSS_FOLDER}/utils
cp patchfiles/tssproperties.c   ${IBMTSS_FOLDER}/utils
cp patchfiles/tsstransmit.c     ${IBMTSS_FOLDER}/utils

# build the project
pushd ${IBMTSS_FOLDER}
autoreconf -i
./configure --prefix=${HOME}/local --disable-tpm-1.2 --enable-debug
make clean && make all -sj
