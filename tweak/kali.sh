#!/bin/sh

echo "run this script after system update!"
echo "$ apt update && apt upgrade -y"

apt install tmux fonts-powerline cherrytree terminator starkiller sshuttle exiftool mono-devel bloodhound docker.io gcc-9-base

# To run bloodhound
#   $ neo4j console
#   - default credentials -> neo4j:neo4j

mkdir .tmux
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
cp ./.tmux.conf ~


cd /opt
git clone https://github.com/sherlock-project/sherlock
git clone https://github.com/NinjaJc01/ssh-backdoor
git clone https://github.com/danielmiessler/SecLists
git clone https://github.com/zaproxy/zap-extensions
git clone https://github.com/saghul/lxd-alpine-builder
git clone https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet
git clone https://github.com/payloadbox/sql-injection-payload-list
git clone https://github.com/swisskyrepo/PayloadsAllTheThings
git clone https://github.com/pentestmonkey/php-reverse-shell
git clone https://github.com/NinjaJc01/joomblah-3
git clone https://github.com/Neohapsis/creddump7
git clone https://github.com/MuirlandOracle/CVE-2019-15107
git clone https://github.com/MuirlandOracle/C-Sharp-Port-Scan
git clone https://github.com/SecureAuthCorp/impacket
cd /opt/impacket && sudo pip3 install . && cd ..
git clone https://github.com/andrew-d/static-binaries
git clone https://github.com/BC-SECURITY/Empire/
cd Empire && ./setup/install.sh && cd ..
git clone https://github.com/internetwache/GitTools
git clone https://github.com/int0x33/nc.exe/
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/
git clone https://github.com/Unode/firefox_decrypt
git clone https://github.com/RUB-NDS/PRET