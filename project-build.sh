#!/bin/bash

# Linux Gemalto PKCS#11 library for Secure Element build script

# Build mode argument management
usage ()
{
    echo 'Usage : ' $0 '<Release|Debug|CodeCoverage|CodeProfile>'
    exit
}

BUILDTYPE=

if [ $# -gt 0 ]; then
    SHELLNOCASEMATCH=`shopt -p nocasematch`
    shopt -s nocasematch
    [[ $1 =~ "release" ]] && BUILDTYPE=Release
    [[ $1 =~ "Release" ]] && BUILDTYPE=Release
    [[ $1 =~ "debug" ]] && BUILDTYPE=Debug
    [[ $1 =~ "Debug" ]] && BUILDTYPE=Debug
    [[ $1 =~ "codecoverage" ]] && BUILDTYPE=CodeCoverage
    [[ $1 =~ "CodeCoverage" ]] && BUILDTYPE=CodeCoverage
    [[ $1 =~ "codeprofile" ]] && BUILDTYPE=CodeProfile
    [[ $1 =~ "CodeProfile" ]] && BUILDTYPE=CodeProfile
    $SHELLNOCASEMATCH
fi

if [ "$BUILDTYPE" = "" ]
then
    usage
fi

echo 'Building in' ${BUILDTYPE} 'mode ...'

# Get the absolute path of this script
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")

# Create the PROJECT_DIR environment variable
export PROJECT_DIR="${SCRIPTPATH}/"

# Save the current path
set SAVEDPATH=`pwd`

PKCS11LIB_SRCDIR=se-pkcs11-lib
SEACCESSLIB_SRCDIR=se-access-lib
TESTP11LIB_SRCDIR=test

# Make sure all files are Linux text files. can be commented out once formated
find ${PKCS11LIB_SRCDIR} -type f -exec dos2unix {} \; 
find ${SEACCESSLIB_SRCDIR} -type f -exec dos2unix {} \;
find ${TESTP11LIB_SRCDIR} -type f -exec dos2unix {} \;
echo "========================================================"
echo "----- Secure Element Access library - Build -----"
echo "========================================================"
cd ${SCRIPTPATH}/${SEACCESSLIB_SRCDIR}/cinterion-modem/build
make clean BUILDTYPE=${BUILDTYPE}
make BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
    cd ${SAVEDPATH}
    exit 1
fi

printf "\n"
echo "========================================================"
echo "----- Secure Element Access library - Installation -----"
echo "========================================================"
make install BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
    cd ${SAVEDPATH}
    exit 1
fi


echo "========================================================"
echo "--------------- Modem Access tests - Build 1/2 ---------"
echo "========================================================"
cd ${SCRIPTPATH}/${SEACCESSLIB_SRCDIR}/test/build
make -f p11-cardmgr-Makefile clean
make -f p11-cardmgr-Makefile BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
   cd ${SAVEDPATH}
   exit 1
fi

printf "\n"

echo "========================================================"
echo "--------------- Modem Access tests - Build 2/2 ---------"
echo "========================================================"

cd ${SCRIPTPATH}/${SEACCESSLIB_SRCDIR}/test/build
make -f cinterion-modem-test-Makefile clean
make -f cinterion-modem-test-Makefile BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
   cd ${SAVEDPATH}
   exit 1
fi

printf "\n"
# Build and install the PKCS#11 library
printf "\n"
echo "=================================================="
echo "----- Secure Element PKCS#11 library - Build -----"
echo "=================================================="
cd ${SCRIPTPATH}
cd ${PKCS11LIB_SRCDIR}/build
make clean BUILDTYPE=${BUILDTYPE} #Can be commented out for faster build
make BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
    cd ${SAVEDPATH}
    exit 1
fi

printf "\n"
echo "========================================================="
echo "----- Secure Element PKCS#11 library - Installation -----"
echo "========================================================="
make install BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
    cd ${SAVEDPATH}
    exit 1
fi

# Display the result
echo "The PKCS#11 library for Secure Element is located :"
ls -ld `find /usr/local/lib/libgtosepkcs11* -print`

printf "\n"


echo "========================================================"
echo "----- Secure Element PKCS#11 library tests - Build -----"
echo "========================================================"
cd ${SCRIPTPATH}
cd ${TESTP11LIB_SRCDIR}/build
make clean BUILDTYPE=${BUILDTYPE}
make BUILDTYPE=${BUILDTYPE}
if [ $? -ne 0 ]; then
    cd ${SAVEDPATH}
    exit 1
fi

cd ${SAVEDPATH}
