#!/bin/bash

die() { echo "$*" 1>&2 ; exit 1; }
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Use the intermediate certificate to sign a server certificate"

CSR=$1
echo "Signing a CSR: $CSR"
if [[ ! -f $CSR ]]; then
    echo "File: $CSR not found"
    exit 1
fi

DIRECTORY=$(dirname "$CSR")
echo "File: $CSR in directory: $DIRECTORY"

OUTPUT_DIRECTORY=$(mktemp -d)
echo "Preparing to sign, output will be in: $OUTPUT_DIRECTORY"
# Very annoyingly, there is no way to get the X509 command to simply copy Subject Alternative Names
# from the CSR into a X509v3 certificate:
# https://stackoverflow.com/questions/33989190/subject-alternative-name-is-not-copied-to-signed-certificate
# The solution is to manually enter them into the extensions config file
# And that can be done by manually extracting them from the request
# Or use the ca command instead of the X509 command

echo 
openssl ca -in "$CSR" -cert $DIR/keys/intermediate-cert.pem \
	-keyfile "$DIR/keys/intermediate-privkey.pem" \
	-config openssl.cnf \
	-name v3_cert \
	-batch \
	-outdir "$OUTPUT_DIRECTORY" \
	-out "$OUTPUT_DIRECTORY/cert.pem" -notext \
	-days 365 \
    || die "couldn't sign the CSR"

# Originally I tried to use the x509 command, but that does not
# copy over subject alt names, which is required for X509v3, which is required for Chrome to work properly
# so this format isn't used. If you create an extensions file and manually
# put the Subject Alt Names in it, the x509 command can be used

#openssl x509 -req -in "$CSR" -CA $DIR/keys/intermediate-cert.pem \
#	-CAkey "$DIR/keys/intermediate-privkey.pem" \
#	-CAcreateserial \
#	-extensions v3_cert -extfile extensions-x509.cnf \
#	-out "$OUTPUT_DIRECTORY/cert.pem" \
#	-days 365 || die "couldn't sign the CSR"

echo "Creating fullchain.pem"
cat "$OUTPUT_DIRECTORY/cert.pem" "$DIR/keys/intermediate-cert.pem" > \
    "$OUTPUT_DIRECTORY/fullchain.pem" || die "couldn't save fullchain.pem"

echo "Done."
