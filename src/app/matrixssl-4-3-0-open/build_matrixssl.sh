#!/bin/sh

#build libwlan
cd ../../../../../../../src/app/matrixssl-4-3-0-open
#make clean
make all -f ./matrix_makefile
cp ./libMatrixssl.a ../../../lib/w800
echo "Build libMatrixssl done."