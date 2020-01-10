#!/bin/bash

#kali linux light installation script , this script will install all necesarry stuff you can pick which scripts you like 
#Download the kali linux light 64bit from here: https://cdimage.kali.org/kali-2019.3/kali-linux-light-2019.3-amd64.iso, verify hash - b6e57c2d9a22cf73ead39d9d58033991bdaa4769c74e1a9d7174e574d1618af8
#tested on kali light 


#Configure Settings
#tools folder
TOOLS="/root/tools"
BIN="/usr/bin" # make sure the folder exists 


echo -e "\e[31m[*]Removing XFCE and installing gnome desktop"m
#remove xfce desktop and install gnome 
apt-get remove -y xfce4 xfce4-places-plugin xfce4-goodies
apt-get install -y gnome-core kali-defaults kali-root-login desktop-base

#updating system
echo -e "\e[31m[*]Updating the system"m
apt update
apt -y upgrade


#these programs exists in Kali Linux's repository and could be installed with apt install 

desktop_installation=(
#----------------------------------dependencies and shit------------------------------# 
ruby-sass
libglib2.0-dev
libgdk-pixbuf2.0-dev
libxml2-utils
gcc
make
bettercap
aircrack-ng
binwalk
bpython
cewl
default-jre
arp-scan
p7zip-full
nbtscan
enum4linux
git
gnome-tweak-tool
gpp-decrypt
guake
hashcat
hping3
hydra
impacket-scripts
install
john
libssl-dev
masscan
macchanger
proxychains
medusa
metasploit-framework
mimikatz
net-tools
nishang
nmap
nodejs
onesixtyone
gobuster
openvpn
mingw-w64
patator
veil-catapult 
python-pip
winetricks
recon-ng
whatweb
ruby-sass
smbmap
sqlmap
statsprocessor
sublist3r
theharvester
torbrowser-launcher
backdoor-factory
commix
upgrade
urlcrazy
windows-binaries
wireshark
yersinia
veil 
) 

for t in ${desktop_installation[@]}; do 
    echo -e "\e[31m[*]Installing: $t"m
	apt -y install $t 
done 


#install golang and configure it 
echo -e "\e[31m[*]Installing: golang"m
apt-get install -y golang
echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
source ~/.profile 
mkdir -p $HOME/go/{src,pkg,bin}
echo "export GOPATH="$HOME/go_projects" >> ~/.profile
echo "export GOBIN="$GOPATH/bin" >> ~/.profile
source ~/.profile 
go env > /dev/null

#check if installation was successful 
if [ $? -eq 0 ]; then 
    echo -e "\e[31mGo installed successfully"m
else 
    echo -e "\e[31mSomething went wrong"m
fi 


#Download chrome 
echo -e "\e[31m[*]Downloading and installing Google Chrome"m
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
dpkg -i google-chrome-stable_current_amd64.deb
rm google-chrome-stable_current_amd64.deb 

#------------------------------------------------------------------------------------
#hacking tool section

echo -e "\e[31m[*]Making tools directory and add it to path"m
mkdir $TOOLS
echo "export PATH=$PATH:$BIN" >> ~/.bashrc
source ~/.bashrc
cd $TOOLS 

#------------------------------------------------------------------------------------
#git section (Downloads scripts from github) 

echo -e "\e[31m[*]Installing: pth-toolkit"m
git clone https://github.com/byt3bl33d3r/pth-toolkit.git pth-toolkit
cd $TOOLS/pth-toolkit 
ln -s $(pwd)/pth* $BIN
cd $TOOLS 

echo -e "\e[31m[*]Installing: Mimikatz"m
cd /usr/share/windows-binaries
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20190813/mimikatz_trunk.7z
7z x mimikatz_trunk.7z -o./mimikatz
rm mimikatz_trunk.7z
cd $TOOLS

echo -e "\e[31m[*]Installing Crackmapexec windows"m
cd /usr/share/windows-binaries 
wget https://github.com/maaaaz/CrackMapExecWin/releases/download/v2.2/CrackMapExecWin_v2.2.zip
unzip CrackMapExecWin_v2.2.zip -d crackmapexec_win
rm CrackMapExecWin_v2.2.zip
cd $TOOLS

echo -e "\e[31m[*]Installing: Hyperion"m
wget https://github.com/nullsecuritynet/tools/raw/master/binary/hyperion/release/Hyperion-1.2.zip
i686-w64-mingw32-c++ Src/Crypter/*.cpp -o hyperion.exe
cp hyperion.exe /usr/share/windows-binaries/ 
rm -r /usr/share/windows-binaries/hyperion 
cd $TOOLS 

#gowitness golang screenshot tool 
echo -e "\e[31m[*]Installing: gowitness"m
mkdir gowitness 
cd gowitness
wget https://github.com/sensepost/gowitness/releases/download/1.2.0/gowitness-linux-amd64 -O gowitness
chmod +x gowitness
ln -s $(pwd)/gowitness $BIN/gowitness
cd $TOOLS

#nosqlmap
echo -e "\e[31m[*]Installing: nosqlmap"m
git clone https://github.com/codingo/NoSQLMap.git nosqlmap
cd nosqlmap
python setup.py install 
chmod +x nosqlmap.py 
ln -s $(pwd)/nosqlmap.py $BIN/nosqlmap
cd $TOOLS

#wordlists 
echo -e "\e[31m[*]Installing: wordlists"m
mkdir $TOOLS/wordlists 
cd $TOOLS/wordlists 
git clone https://github.com/fuzzdb-project/fuzzdb.git
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/danielmiessler/RobotsDisallowed.git
git clone https://github.com/berzerk0/Probable-Wordlists.git
cd $TOOLS

echo -e "\e[31m[*]Installing: unicorn trustedsec"m
#unicorn
git clone https://github.com/trustedsec/unicorn.git unicorn
cd unicorn 
chmod +x unicorn.py 
ln -s $(pwd)/unicorn.py $BIN/unicorn
cd $TOOLS

echo -e "\e[31m[*]Installing: stickykeeslayer"m
#sticky-key-slayer
apt -y install imagemagick xdotool parallel bc
git clone https://github.com/linuz/Sticky-Keys-Slayer.git sticky-slayer
cd sticky-slayer
ln -s $(pwd)/stickyKeysSlayer.sh $BIN/stickyslayer
cd $TOOLS

echo -e "\e[31m[*]Installing: office365 enumerator"m
#office365enum
git clone https://bitbucket.org/grimhacker/office365userenum.git
cd office365userenum
chmod +x office365userenum.py
ln -s $(pwd)/office365userenum.py $BIN/office365userenum
cd $TOOLS

echo -e "\e[31m[*]Installing: pyobfuscate"m
#pyobfuscate
git clone https://github.com/astrand/pyobfuscate.git
cd pyobfuscate
python setup.py install 
ln -s $(pwd)/pyobfuscate.py $BIN/pyobfuscate
cd $TOOLS

echo -e "\e[31m[*]Installing: goscripts subfinder, gitrob, httprobe etc"m
go get github.com/subfinder/subfinder
ln -s $GOPATH/bin/subfinder $BIN/subfinder
go get github.com/michenriksen/gitrob
ln -s $GOPATH/bin/gitrob $BIN/gitrob
go get -u github.com/tomnomnom/httprobe
ln -s $GOPATH/bin/httprobe $BIN/httprobe

echo -e "\e[31m[*]Installing: Windows Exploit Suggester and snarf"m
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
git clone https://github.com/purpleteam/snarf.git

echo -e "\e[31m[*]Installing: cmsmap"m
#cmsmap
git clone https://github.com/Dionach/CMSmap.git cmsmap
cd cmsmap
pip3 install .
cd $TOOLS

echo -e "\e[31m[*]Installing: webshells"m
git clone https://github.com/BlackArch/webshells.git

echo -e "\e[31m[*]Installing: hatecrack"m
git clone https://github.com/trustedsec/hate_crack.git hate-crack
 
 
echo -e "\e[31m[*]Installing: jexboss"m
#jexboss
git clone https://github.com/joaomatosf/jexboss.git
cd jexboss
chmod +x jexboss.py 
ln -s $(pwd)/jexboss.py $BIN/jexboss
cd $TOOLS

echo -e "\e[31m[*]Installing: spraywmi with fix for kali"m
#spraywmi 
git clone https://github.com/trustedsec/spraywmi.git
cd spraywmi 
dpkg -y --add-architecture i386 && apt-get update && apt-get install libpam0g:i386 libpopt0:i386
chmod +x spraywmi.py
mv wmis wmis.orig
cp /usr/bin/pth-wmis ./wmis
ln -s $(pwd)/spraywmi.py $BIN/spraywmi
cd $TOOLS 

echo -e "\e[31m[*]Installing: xsstrike"m
#xsstrike
git clone https://github.com/s0md3v/XSStrike.git xsstrike
cd xsstrike 
chmod +x xsstrike.py
ln -s $(pwd)/xsstrike.py $BIN/xsstrike.py
cd $TOOLS 

echo -e "\e[31m[*]Installing: cors-poc"m
#cors-poc
git clone https://github.com/trustedsec/cors-poc cors-poc

echo -e "\e[31m[*]Installing: eggressbuster (outbound port finder)"m
#egressbuster
git clone https://github.com/trustedsec/egressbuster.git
cd egressbuster 
ln -s $(pwd)/egressbuster.py $BIN/egressbuster
cd $TOOLS

echo -e "\e[31m[*]Installing: sidestep AV bypass"m
#sidestep
git clone https://github.com/codewatchorg/SideStep.git sidestep
cd sidestep
chmod +x sidestep.py 
ln -s $(pwd)/sidestep.py $BIN/sidestep
cd $TOOLS

echo -e "\e[31m[*]Installing: bfac "m
#bfac
git clone https://github.com/mazen160/bfac.git
cd bfac 
python setup.py install
cd $TOOLS

echo -e "\e[31m[*]Installing: Docker for Kali "m
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install docker-ce

echo -e "\e[31m[*]Installing: ssh-audit"m
#ssh-audit
git clone https://github.com/arthepsy/ssh-audit.git ssh-audit
cd ssh-audit 
ln -s $(pwd)/ssh-audit.py $BIN/ssh-audit
cd $TOOLS

echo -e "\e[31m[*]Installing: simplymail"m
#simplyemail
git clone https://github.com/killswitch-GUI/SimplyEmail.git simplyemail
cd simplyemail
./setup/setup.sh
cd $TOOLS 

echo -e "\e[31m[*]Installing: linkfinder"m
#linkfinder
git clone https://github.com/GerbenJavado/LinkFinder.git linkfinder
python setup.py install
chmod +x linkfinder.py 
ln -s $(pwd)/linkfinder.py $BIN/linkfinder
cd $TOOLS

echo -e "\e[31m[*]Installing: droopescan"m
#droopescan
git clone https://github.com/droope/droopescan.git
cd droopescan
python setup.py 
pip install -r requirements.txt
cd $TOOLS

echo -e "\e[31m[*]Installing: crackmapexec"m
#crackmapexec
apt-get install -y libssl-dev libffi-dev python-dev build-essential python-pip
pip install crackmapexec

echo -e "\e[31m[*]Installing: dirsearch"m
#dirsearch
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
chmod +x dirsearch.py
sudo ln -s $(pwd)/dirsearch.py $BIN/dirsearch
cd $TOOLS

echo -e "\e[31m[*]Installing: parameth"m
#parameth
git clone https://github.com/maK-/parameth.git
cd parameth
chmod +x parameth.py
sudo ln -s $(pwd)/parameth.py $BIN/parameth
cd $TOOLS 

echo -e "\e[31m[*]Installing: InSpy"m
git clone https://github.com/leapsecurity/InSpy inspy 
cd inspy
chmod +x InSpy.py
sudo ln -s $(pwd)/InSpy.py $BIN/inspy
cd $TOOLS

echo -e "\e[31m[*]Installing: bloodhound"m
#bloodhound
apt-get install bloodhound

echo -e "\e[31m[*]Installing: Powershell and Powershell tools"m
#Install various powershell tools (for me it's good for various occations like internals where I need tools for my windows machine for example)
apt update && apt -y install curl gnupg apt-transport-https
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/powershell.list
apt update
apt -y install powershell
mkdir $TOOLS/powershell-tools 
cd $TOOLS/powershell-tools
git clone https://github.com/dafthack/MailSniper.git
git clone https://github.com/jseidl/Babadook.git badabook
git clone https://github.com/nyxgeek/o365recon.git 
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/samratashok/nishang.git
https://github.com/HarmJ0y/PowerUpSQL.git
https://github.com/HarmJ0y/PowerUp.git
https://github.com/HarmJ0y/ImpDump.git
https://github.com/HarmJ0y/Inveigh.git
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -o sharphound.ps1 
git clone https://github.com/sense-of-security/ADRecon.git
git clone https://github.com/GoFetchAD/GoFetch.git
git clone https://github.com/Raikia/Get-ReconInfo.git
git clone https://github.com/FortyNorthSecurity/WMIOps.git
git clone https://github.com/Raikia/CredNinja.git
git clone https://github.com/peewpw/Invoke-PSImage
cd $TOOLS 

msfdb init 

echo -e "\e[31m[*]Installing: empire"m
#empire 
git clone https://github.com/EmpireProject/Empire.git empire
cd empire 
echo "toor" | ./setup/install.sh./setup/install.sh
pip install pefile
sudo ln -s $(pwd)/empire $BIN/empire
cd $TOOLS 

echo -e "\e[31m[*]Fixing last settings"m
/usr/share/veil/config/setup.sh --force --silent


echo -e "\e[31m[*]Installing: wireshark"m
apt install -y wireshark
apt --fix-broken install -y 

echo -e "\e[31m[*]Installing Sysinternals"m
cd /usr/share/windows-binaries 
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip SysinternalsSuite.zip -d sysinternals 
rm SysinternalsSuite.zip
wget https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.exe?raw=true -o sharphound.exe
ln -s /usr/share/doc/python3-impacket/examples/* $BIN

cd $TOOLS 
echo -e "\e[31m[*]Finished Installation!"m
