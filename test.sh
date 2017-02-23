#!/bin/bash
#
# A test script for Xiami's CA.sh
#

prog=`realpath $BASH_SOURCE`
wd=`dirname $prog`
S="$wd/CA.sh"

[ -d "test" ] && { echo "Remove test directory first, please."; exit 1; }
mkdir -p test

mkdir test/{root,inter}
pushd test/root
$S init -g rsa:4096 "/C=CN/O=Test Inc./CN=Test Root CA/emailAddress=ca@example.com" || exit 1
$S genocspcert -g rsa:2048 "/C=CN/O=Test Inc./CN=Test Root CA OCSP Responder/" || exit 1
$S newca -g rsa:2048 "/C=CN/O=Test Inc./CN=Test Intermediate CA/" ca_intermediate_v3ext ../inter || exit 1
$S gencrl || exit 1
popd
pushd test/inter
$S genocspcert -g rsa:2048 "/C=CN/O=Test Inc./CN=Test Intermediate CA OCSP Responder/" || exit 1
$S genocspcert -g rsa:2048 "/C=CN/O=Test Inc./CN=Test Intermediate CA OCSP Responder 2/" && exit 1
$S newcert -g rsa:2048 "/C=CN/O=Test Inc./CN=example.com/" --san "IP:127.0.0.1" --san "DNS:www.example.com" tls_client_v3ext || exit 1
torevoke=`realpath cert/$(<last_srl).pem` || exit 1
$S newcert -g rsa:2048 "/C=CN/O=Test Inc./CN=example.com/" --san "IP:127.0.0.1" --san "DNS:www.example.com" tls_server_v3ext || exit 1
$S revoke "$torevoke" --caarg "-crl_reason superseded" || exit 1
$S gencrl || exit 1
popd

echo "Test succeed!"

rm -rf test
