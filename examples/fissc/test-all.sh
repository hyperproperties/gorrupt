#!/bin/bash
set -e

echo "Running tests in VerifyPIN_0..."
(cd ./VerifyPIN_0/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_1..."
(cd ./VerifyPIN_1/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_2..."
(cd ./VerifyPIN_2/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_3..."
(cd ./VerifyPIN_3/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_4..."
(cd ./VerifyPIN_4/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_5..."
(cd ./VerifyPIN_5/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_6..."
(cd ./VerifyPIN_6/ && sh ./test.sh) || true
echo "Running tests in VerifyPIN_7..."
(cd ./VerifyPIN_7/ && sh ./test.sh) || true