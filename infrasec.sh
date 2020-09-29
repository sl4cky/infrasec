#!/bin/bash

#Ubuntu clean installation script (tested on clean ubuntu 20.04.1 LTS)

#Configure Settings
#tools folder
TOOLS="/root/tools"
BIN="/usr/bin" # make sure the folder exists 


#updating system
echo -e "\e[31m[*]  Updating the system"
apt-get -y update > /dev/null
apt-get -y upgrade > /dev/null


#these programs exists in Kali Linux's repository and could be installed with apt-get install 

desktop_installation=(
#----------------------------------dependencies and shit------------------------------# 
ruby-sass
libglib2.0-dev
libgdk-pixbuf2.0-dev
libxml2-utils
gcc
make
binwalk
bpython
bpython3
default-jre
arp-scan
p7zip-full
nbtscan
mlocate
git
gnome-tweak-tool
rdesktop
guake
hping3
hydra
john
libssl-dev
masscan
macchanger
proxychains
medusa
net-tools
nmap
nodejs
pipx
onesixtyone
gobuster
openvpn
mingw-w64
patator
python3-pip
winetricks
recon-ng
whatweb
smbmap
yersinia 
) 

for t in ${desktop_installation[@]}; do 
    echo -e "\e[31m [*] Installing: $t"
	apt-get -y install $t > /dev/null
done 



#Download chrome 
echo -e "\e[31m [*] Downloading and installing Google Chrome"
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb > /dev/null
dpkg -i google-chrome-stable_current_amd64.deb > /dev/null
rm google-chrome-stable_current_amd64.deb > /dev/null

#------------------------------------------------------------------------------------
#hacking tool section

echo -e "\e[31m[*] Making tools directory and add it to path"
mkdir $TOOLS
echo "export PATH=$PATH:$BIN" >> ~/.bashrc
source ~/.bashrc
cd $TOOLS 

#------------------------------------------------------------------------------------
#git section (Downloads scripts from github) 
echo -e "\e[31m[*] Installing: pth-toolkit"
git clone https://github.com/byt3bl33d3r/pth-toolkit.git pth-toolkit > /dev/null
cd $TOOLS/pth-toolkit 
ln -s $(pwd)/pth* $BIN
cd $TOOLS 

echo -e "\e[31m[*] Installing: Mimikatz"
cd $TOOLS
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20190813/mimikatz_trunk.7z > /dev/null
7z x mimikatz_trunk.7z -o./mimikatz > /dev/null
rm mimikatz_trunk.7z > /dev/null
cd $TOOLS > /dev/null

echo -e "\e[31m[*] Installing Crackmapexec"
python3 -m pip install pipx > /dev/null
pipx ensurepath > /dev/null
pipx install crackmapexec > /dev/null


#gowitness golang screenshot tool 
echo -e "\e[31m[*] Installing: gowitness"
mkdir gowitness 
cd gowitness
wget https://github.com/sensepost/gowitness/releases/download/2.1.1/gowitness-2.1.1-linux-amd64 -o gowitness > /dev/null
chmod +x gowitness > /dev/null
ln -s $(pwd)/gowitness $BIN/gowitness > /dev/null
cd $TOOLS


#wordlists 
echo -e "\e[31m[*] Installing: wordlists"
mkdir $TOOLS/wordlists 
cd $TOOLS/wordlists 
git clone https://github.com/fuzzdb-project/fuzzdb.git > /dev/null 
git clone https://github.com/danielmiessler/SecLists.git > /dev/null
git clone https://github.com/danielmiessler/RobotsDisallowed.git > /dev/null
git clone https://github.com/berzerk0/Probable-Wordlists.git > /dev/null
cd $TOOLS > /dev/null

echo -e "\e[31m[*] Installing: SQLMAP"
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap
cd sqlmap 
ln -s $(pwd)/sqlmap.py $BIN/sqlmap > /dev/null
cd $TOOLS


echo -e "\e[31m[*] Installing: unicorn trustedsec"
#unicorn
git clone https://github.com/trustedsec/unicorn.git unicorn > /dev/null
cd unicorn > /dev/null 
chmod +x unicorn.py > /dev/null 
ln -s $(pwd)/unicorn.py $BIN/unicorn > /dev/null
cd $TOOLS > /dev/null

echo -e "\e[31m[*] Installing: stickykeeslayer"
#sticky-key-slayer
apt-get -y install imagemagick xdotool parallel bc > /dev/null
git clone https://github.com/linuz/Sticky-Keys-Slayer.git sticky-slayer > /dev/null
cd sticky-slayer > /dev/null
ln -s $(pwd)/stickyKeysSlayer.sh $BIN/stickyslayer > /dev/null
cd $TOOLS > /dev/null

echo -e "\e[31m[*] Installing: office365 enumerator"
#office365enum
git clone https://bitbucket.org/grimhacker/office365userenum.git > /dev/null
cd office365userenum > /dev/null
chmod +x office365userenum.py > /dev/null
ln -s $(pwd)/office365userenum.py $BIN/office365userenum > /dev/null
cd $TOOLS > /dev/null

echo -e "\e[31m[*] Installing: goscripts subfinder, gitrob, httprobe etc"
go get github.com/subfinder/subfinder > /dev/null
ln -s $GOPATH/bin/subfinder $BIN/subfinder > /dev/null
go get github.com/michenriksen/gitrob > /dev/null
ln -s $GOPATH/bin/gitrob $BIN/gitrob > /dev/null
go get -u github.com/tomnomnom/httprobe > /dev/null
ln -s $GOPATH/bin/httprobe $BIN/httprobe > /dev/null
 

echo -e "\e[31m[*] Installing: Windows Exploit Suggester and snarf"
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git > /dev/null
git clone https://github.com/purpleteam/snarf.git > /dev/null


echo -e "\e[31m[*] Installing: cmsmap"
#cmsmap
git clone https://github.com/Dionach/CMSmap.git cmsmap > /dev/null
cd cmsmap > /dev/null
pip3 install .
cd $TOOLS

echo -e "\e[31m[*] Installing: webshells"
git clone https://github.com/BlackArch/webshells.git > /dev/null
 

echo -e "\e[31m[*] Installing: sublister"
git clone https://github.com/aboul3la/Sublist3r.git -o sublister > /dev/null
cd sublister > /dev/null
sudo pip install -r requirements.txt > /dev/null
ln -s $TOOLS/Sublist3r/sublist3r.py /usr/bin/sublister > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: hatecrack"
git clone https://github.com/trustedsec/hate_crack.git hate-crack > /dev/null


echo -e "\e[31m[*] Installing: metasploit framework"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
chmod 755 msfinstall && \ > /dev/null
./msfinstall > /dev/null
rm ./msfinstall > /dev/null
 

echo -e "\e[31m[*] Installing: jexboss"
#jexboss
git clone https://github.com/joaomatosf/jexboss.git > /dev/null
cd jexboss > /dev/null
chmod +x jexboss.py > /dev/null 
ln -s $(pwd)/jexboss.py $BIN/jexboss > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: spraywmi with fix for kali"
#spraywmi 
git clone https://github.com/trustedsec/spraywmi.git > /dev/null
cd spraywmi > /dev/null  
dpkg -y --add-architecture i386 && apt-get-get update && apt-get-get install libpam0g:i386 libpopt0:i386 > /dev/null
chmod +x spraywmi.py > /dev/null
mv wmis wmis.orig > /dev/null
cp /usr/bin/pth-wmis ./wmis > /dev/null
ln -s $(pwd)/spraywmi.py $BIN/spraywmi > /dev/null
cd $TOOLS > /dev/null 

echo -e "\e[31m[*] Installing: xsstrike"
#xsstrike
git clone https://github.com/s0md3v/XSStrike.git xsstrike > /dev/null
cd xsstrike > /dev/null 
chmod +x xsstrike.py > /dev/null
ln -s $(pwd)/xsstrike.py $BIN/xsstrike.py > /dev/null
cd $TOOLS > /dev/null

echo -e "\e[31m[*] Installing: cors-poc"
#cors-poc
git clone https://github.com/trustedsec/cors-poc cors-poc > /dev/null 


echo -e "\e[31m[*] Installing: eggressbuster (outbound port finder)"
#egressbuster
git clone https://github.com/trustedsec/egressbuster.git > /dev/null
cd egressbuster > /dev/null 
ln -s $(pwd)/egressbuster.py $BIN/egressbuster > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: sidestep AV bypass"
#sidestep
git clone https://github.com/codewatchorg/SideStep.git sidestep > /dev/null
cd sidestep > /dev/null
chmod +x sidestep.py > /dev/null 
ln -s $(pwd)/sidestep.py $BIN/sidestep > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: bfac"
#bfac
git clone https://github.com/mazen160/bfac.git > /dev/null
cd bfac > /dev/null 
python setup.py install > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: Docker"
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-get-key add - > /dev/null
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' > /etc/apt-get/sources.list.d/docker.list > /dev/null
apt-get-get update > /dev/null
apt-get-get install docker-ce > /dev/null


echo -e "\e[31m[*] Installing: ssh-audit"
#ssh-audit
git clone https://github.com/arthepsy/ssh-audit.git ssh-audit > /dev/null
cd ssh-audit > /dev/null 
ln -s $(pwd)/ssh-audit.py $BIN/ssh-audit > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: simplymail"
#simplyemail
git clone https://github.com/killswitch-GUI/SimplyEmail.git simplyemail > /dev/null
cd simplyemail > /dev/null
./setup/setup.sh > /dev/null
cd $TOOLS > /dev/null 


echo -e "\e[31m[*] Installing: linkfinder"
#linkfinder
git clone https://github.com/GerbenJavado/LinkFinder.git linkfinder > /dev/null
python setup.py install > /dev/null
chmod +x linkfinder.py > /dev/null 
ln -s $(pwd)/linkfinder.py $BIN/linkfinder > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: droopescan"
#droopescan
git clone https://github.com/droope/droopescan.git > /dev/null
cd droopescan > /dev/null
python setup.py  > /dev/null
pip install -r requirements.txt > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: crackmapexec"
#crackmapexec
apt-get-get install -y libssl-dev libffi-dev python-dev build-essential python-pip > /dev/null
pip install crackmapexec > /dev/null


echo -e "\e[31m[*] Installing: dirsearch"
#dirsearch
git clone https://github.com/maurosoria/dirsearch.git > /dev/null
cd dirsearch > /dev/null
chmod +x dirsearch.py > /dev/null
sudo ln -s $(pwd)/dirsearch.py $BIN/dirsearch > /dev/null
cd $TOOLS > /dev/null


echo -e "\e[31m[*] Installing: parameth"
#parameth
git clone https://github.com/maK-/parameth.git > /dev/null
cd parameth > /dev/null
chmod +x parameth.py > /dev/null
sudo ln -s $(pwd)/parameth.py $BIN/parameth > /dev/null
cd $TOOLS > /dev/null 


echo -e "\e[31m[*] Installing: InSpy"
git clone https://github.com/leapsecurity/InSpy inspy > /dev/null  
cd inspy > /dev/null
chmod +x InSpy.py > /dev/null
sudo ln -s $(pwd)/InSpy.py $BIN/inspy > /dev/null
cd $TOOLS

echo -e "\e[31m[*] Installing: Powershell and Powershell tools"
#Install various powershell tools (for me it's good for various occations like internals where I need tools for my windows machine for example)
apt-get update && apt-get -y install curl gnupg apt-get-transport-https > /dev/null
curl https://packages.microsoft.com/keys/microsoft.asc | apt-get-key add - > /dev/null
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt-get/sources.list.d/powershell.list > /dev/null
apt-get -y update > /dev/null
apt-get -y install powershell > /dev/null
mkdir $TOOLS/powershell-tools > /dev/null 
cd $TOOLS/powershell-tools > /dev/null
git clone https://github.com/dafthack/MailSniper.git > /dev/null
git clone https://github.com/jseidl/Babadook.git badabook > /dev/null
git clone https://github.com/nyxgeek/o365recon.git > /dev/null 
git clone https://github.com/PowerShellMafia/PowerSploit.git > /dev/null
git clone https://github.com/samratashok/nishang.git > /dev/null
git clone https://github.com/HarmJ0y/PowerUpSQL.git > /dev/null
git clone https://github.com/HarmJ0y/PowerUp.git > /dev/null
git clone https://github.com/HarmJ0y/ImpDump.git > /dev/null
git clone https://github.com/HarmJ0y/Inveigh.git > /dev/null
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -o sharphound.ps1 > /dev/null  
git clone https://github.com/sense-of-security/ADRecon.git > /dev/null
git clone https://github.com/GoFetchAD/GoFetch.git > /dev/null
git clone https://github.com/Raikia/Get-ReconInfo.git > /dev/null
git clone https://github.com/FortyNorthSecurity/WMIOps.git > /dev/null
git clone https://github.com/Raikia/CredNinja.git > /dev/null
git clone https://github.com/peewpw/Invoke-PSImage > /dev/null
cd $TOOLS 


echo -e "\e[31m[*] Configuring metasploit framework"
msfdb init 

echo -e "\e[31m[*] Installing: empire"
#empire 
git clone https://github.com/EmpireProject/Empire.git empire
cd empire 
echo "toor" | ./setup/install.sh
pip install pefile
sudo ln -s $(pwd)/empire/empire $BIN/empire
cd $TOOLS 

echo -e "\e[31m[*] Installing: Impacket"
https://github.com/SecureAuthCorp/impacket.git 
cd impacket
pip3 install .
ln -s examples/* $BIN
cd $TOOLS


echo -e "\e[31m[*] Installing Sysinternals"
cd /usr/share/windows-binaries 
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip SysinternalsSuite.zip -d sysinternals 
rm SysinternalsSuite.zip
wget https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.exe?raw=true -o sharphound.exe


echo -e "\e[31m[*] Installing: wireshark"
apt-get install -y wireshark
apt-get --fix-broken install -y 

cd $TOOLS 
echo -e "\e[31m[*] Finished Installation!"
