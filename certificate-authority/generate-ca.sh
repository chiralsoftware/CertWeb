#!/bin/bash

die() { echo "$*" 1>&2 ; exit 1; }

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

KEYS="$DIR/keys"
source "$DIR/vars.sh"

if [[ ! -d "$KEYS" ]]; then
    echo "Creating directory: $KEYS"
    mkdir "$KEYS"
fi

#echo "Generating a CA root key"

#echo "Step 1: generating a private key"
#openssl genrsa  -out $KEYS/root-privkey.pem 2048 || die "couldn't generate the root private key"

echo "Deleting all old keys and certificates"
rm -f $KEYS/*
touch $KEYS/database $KEYS/cert-database $KEYS/cert-database.attr
echo 01 > $KEYS/serial

# using the req command with the -new option means that it will generate the RSA key in one step
echo "Generating a self-signed certificate to serve as the CA root certificate"
openssl req -config "$DIR/openssl.cnf" \
	-new -keyout $KEYS/root-privkey.pem -nodes \
	-x509 -days 3650 -out $KEYS/root-ca.crt \
	-extensions v3_ca \
	-subj "/CN=$CA_ROOT" || die "couldn't generate a self-signed root"

# hint: the key fact there is using -x509 generates a self-signed X509 certificate
# without the -x509 option it generates a request, not a self-signed X509

echo

echo "Generating the intermediate certificate CSR"

# See: https://superuser.com/questions/738612/openssl-ca-keyusage-extension

openssl req -new -nodes \
	-keyout $KEYS/intermediate-privkey.pem -days 3650 \
	-out $KEYS/intermediate-csr.pem -subj "/CN=$CA_INTERMEDIATE" || \
    die "couldn't create request"

echo "Intermediate CSR has been generated. Now signing it."


# we shoudl also be able to use the openssl x509 commnad to sign a cert
# which should be simpler but this also works
openssl ca -in $KEYS/intermediate-csr.pem \
	-cert "$KEYS/root-ca.crt" -keyfile "$KEYS/root-privkey.pem" \
	-config openssl.cnf \
	-outdir "$KEYS" \
	-extensions v3_ica \
	-batch \
	-out "$KEYS/intermediate-cert.pem" -notext \
	-days 365 \
	-batch \
    || die "couldn't sign the CSR"

rm -f "$KEYS/intermediate-csr.pem"

echo "Creation of CA is complete.."
echo "Certificate authority: $KEYS/root-ca.crt"
openssl x509 -in $KEYS/root-ca.crt -noout \
	-subject -issuer -dates -purpose -fingerprint 
echo
echo "Intermediate certificate: $KEYS/intermediate-cert.pem"
openssl x509 -in "$KEYS/intermediate-cert.pem" -noout \
	-subject -issuer -dates -purpose -fingerprint 
echo
