#!/bin/sh

apt update && apt upgrade -y

cd /opt
git clone https://github.com/NinjaJc01/ssh-backdoor
git clone https://github.com/danielmiessler/SecLists
git clone https://github.com/zaproxy/zap-extensions
git clone https://github.com/saghul/lxd-alpine-builder
git clone https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet
git clone https://github.com/payloadbox/sql-injection-payload-list
git clone https://github.com/swisskyrepo/PayloadsAllTheThings
git clone https://github.com/NinjaJc01/joomblah-3