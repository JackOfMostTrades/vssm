#!/bin/sh

DIRNAME=`dirname $0`
cd ${DIRNAME}

while [ 1 ]; do
    ${DIRNAME}/vssm
    sleep 1
done
