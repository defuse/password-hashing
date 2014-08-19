#!/bin/bash

HASH_HITS=$(                                    \
    grep -R -i hash * |                         \
    grep -v PBKDF2_HASH_ALGORITHM |             \
    grep -v "The hash algorithm to use" |       \
    grep -v "hash_algos" |                      \
    grep -v "unsupported hash algorithm" |      \
    grep -v "hash_pbkdf2" |                     \
    grep -v "hash_hmac" |                       \
    grep -v "\$hash_length" |                   \
    grep -v "hashing-security.htm" |          \
    grep -v "hash("                             \
)

if [[ -n $HASH_HITS ]]; then
    echo "$HASH_HITS"
    echo "FAILED! There are non-whitelisted occurances of the word 'hash!'"
    exit 1
else
    echo "passed."
    exit 0
fi
