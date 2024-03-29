#!/bin/sh

echo "run this script after system update!"
echo "$ apt update && apt upgrade -y"

apt install tmux fonts-powerline cherrytree terminator starkiller sshuttle exiftool mono-devel bloodhound docker.io gcc-9-base simplescreenrecorder

# install zsh autocompleat plugins is needed
# sudo apt install zsh-syntax-highlighting zsh-autosuggestions

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
git clone https://github.com/ignis-sec/Pwdb-Public
# add custom content to dirlist
echo "wp-login.php" >> /opt/SecLists/Discovery/Web-Content/big.txt
git clone https://github.com/zaproxy/zap-extensions
git clone https://github.com/saghul/lxd-alpine-builder
git clone https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
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
git clone https://github.com/rbsec/dnscan
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
wget http://downloads.sourceforge.net/project/pentbox18realised/pentbox-1.8.tar.gz
tar xvf pentbox-1.8.tar.gz
rm pentbox-1.8.tar.gz
# Nishang is a framework and collection of scripts and payloads which enables
# usage of PowerShell for offensive security
git clone https://github.com/samratashok/nishang
git clone https://github.com/carlospolop/PEASS-ng
git clone https://github.com/rebootuser/LinEnum
# Sigma translate search query to SIEMs
# Online version - https://uncoder.io/
git clone https://github.com/Neo23x0/sigma
git clone https://github.com/unode/firefox_decrypt

# To correctly decrypt Windows 10 SAM
git clone https://github.com/Tib3rius/creddump7
pip3 install pycrypto
python3 creddump7/pwdump.py SYSTEM SAM

# Sysmon config
git clone https://github.com/SwiftOnSecurity/sysmon-config
git clone https://github.com/ion-storm/sysmon-config

# Kerberose attack
git clone https://github.com/GhostPack/Rubeus

# Post exploitation - find sensitive data
git clone https://github.com/AlessandroZ/LaZagne

# Windows kernel exploits
git clone https://github.com/SecWiki/windows-kernel-exploits

# Yara system analysis
git clone https://github.com/Neo23x0/Loki
git clone https://github.com/Neo23x0/Loki
git clone https://github.com/Neo23x0/yarGen.git

# Windows PrintNightmare exploit
git clone https://github.com/cube0x0/CVE-2021-1675

#Windows UAC bypass
https://github.com/hfiref0x/UACME

# Linux OS passwords and secrets dump
git clone https://github.com/huntergregal/mimipenguin.git
git clone https://github.com/controlplaneio/truffleproc.git
git clone https://github.com/blendin/3snake.git
git clone https://github.com/nopernik/SSHPry2.0.git
git clone https://github.com/0xmitsurugi/gimmecredz.git

##################################################################
# Disable ipv6
# net.ipv6.conf.all.disable_ipv6=1
# net.ipv6.conf.default.disable_ipv6=1
# net.ipv6.conf.lo.disable_ipv6=1
# sudo sysctl -p