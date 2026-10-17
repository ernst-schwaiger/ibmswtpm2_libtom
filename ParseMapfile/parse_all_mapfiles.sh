#!/bin/bash

FOOTPRINT_FOLDER="/home/ernst/projects/DiplomaThesis/STM32TPM/Doc/Thesis/footprint"
PYTHON_MODULE="/home/ernst/projects/PortSwTpm2LibTom/ibmswtpm2_libtom/ParseMapfile/parse_mapfile.py"

echo "Start LibtomMath - O0 ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_O0_LTM.json
echo "End LibtomMath - O0 ----------------------------------"

echo "Start LibtomMath - O2 ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_O2_LTM.json
echo "End LibtomMath - O2 ----------------------------------"

echo "Start LibtomMath - OS ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_OS_LTM.json
echo "End LibtomMath - OS ----------------------------------"


echo "Start TomsFastMath - O0 ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_O0_TFM.json
echo "End TomsFastMath - O0 ----------------------------------"

echo "Start TomsFastMath - O2 ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_O2_TFM.json
echo "End TomsFastMath - O2 ----------------------------------"

echo "Start TomsFastMath - O2 unrolled ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_O2_TFM_unrolled.json
echo "End TomsFastMath - O2 unreolled ----------------------------------"

echo "Start TomsFastMath - OS ----------------------------------"
python3 ${PYTHON_MODULE} ${FOOTPRINT_FOLDER}/STM32TPM_CM4_OS_TFM.json
echo "End TomsFastMath - OS ----------------------------------"
