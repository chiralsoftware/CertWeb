#!/bin/bash

echo "Using curl to test the installed certificate."
HOST=$1
INTERNAL_NAME=$2

if [[ -z "$HOST" ]] || [[ -z "$INTERNAL_NAME" ]]; then
    echo "Usage:"
    echo
    echo "  request.sh real-host.chiralsoftware.com example.local"
    echo
    echo "where real-host.chiralsoftware.com resolves to a real IP address"
    echo "and example.local is the value of the X509 certificate which was signed."
    exit 1
fi


IP_ADDRESS=$(getent hosts $HOST | awk '{ print $1 }' | head -1)

echo "Real host name: $HOST"
echo "Internal DNS name: $INTERNAL_NAME"
echo "Real IP address: $IP_ADDRESS"

die() { echo "$*" 1>&2 ; exit 1; }

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

curl -v --cacert "$DIR/root-ca.pem" --resolve $INTERNAL_NAME:443:$IP_ADDRESS https://$INTERNAL_NAME:443/
