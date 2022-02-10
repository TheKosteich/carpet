#!/usr/bin/python3

import argparse

parser = argparse.ArgumentParser(
    description='Making file with unique value of NTLMv2 hashes.'
                'Nice to use with "responder".'
)
parser.add_argument('hashfile', help='Path to hashes file')
parser.add_argument('-o', '--out-file', help='Output file name')
args = parser.parse_args()

hash_dict = {}

with open(args.hashfile, 'r') as hashfile:
    for hash in hashfile.readlines():
        splitted_hash = hash.split(':')
        key = f'{splitted_hash[0]} {splitted_hash[2]}'

        if key not in hash_dict:
            hash_dict[key] = hash

try:
    with open(args.out_file, 'a') as out_file:
        for key, value in hash_dict.items():
            out_file.write(value)
except TypeError:
    print(*hash_dict.values(), sep='')
