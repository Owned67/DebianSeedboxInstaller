# /bin/bash

#On commence par vérifier que le script est lancé en tant que root
if [ `whoami` != "root" ]; then 
echo "*********************************************************************************
Vous devez avoir les privilèges super-utilisateur (root) pour exécuter ce script.
*********************************************************************************"
exit 1
fi 

#On demande les infos nécessaires
echo "Entrez un login"
read user
echo "Entrez un mot de passe"
read htpassword
echo "Entrez un nom de domain"
read domain
echo "Entrez la vitesse limite de téléchargement (en Ko/s, 0 pour illimité)"
read downspeed
echo "Entrez la vitesse limite de téléversement (en Ko/s, 0 pour illimité)"
read upspeed
echo "Entrez un mot de passe root pour la base de données"
read bddpassword


#On configure les locales
rm -f /etc/locale.gen
echo "fr_FR.UTF-8 UTF-8
en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen

if [ $? != 0 ]; then
echo "Problème de locales"
exit 2
fi

#On peut donc mettre à jour le système et installer les paquets nécessaires.
apt-get update -y && apt-get upgrade -y
if [ $? != 0 ]; then
echo "Problème de mise à jour"
exit 3
fi

DEBIAN_FRONTEND='noninteractive' command apt-get install -y locales apache2 apache2-doc apache2-mpm-prefork apache2-utils libexpat1 ssl-cert libapache2-mod-php5 php5 php5-common php5-curl php5-dev php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-mysql php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl libapache2-mod-scgi build-essential make gcc autoconf curl libcurl3 libcurl4-openssl-dev zip unzip libc6-dev linux-libc-dev diffutils wget bzip2 screen ffmpeg libcppunit-dev libncurses5-dev libncursesw5-dev subversion libsigc++-1.2-5c2 libsigc++-dev libsigc++-2.0-0c2a libsigc++-2.0-dev libsigc++-2.0-doc libsigc++-1.2-dev imagemagick zsh git openssl unrar-free mp3info libcurl4-openssl-dev mysql-server smbclient libzen0 libmediainfo0 mediainfo glibc-2.13-1 xdg-utils python2.7 phpmyadmin apg

if [ $? != 0 ]; then
echo "Problème d'installation de paquets"
exit 4
fi

MYSQL_PASSWORD="$(command apg -q -a  0 -n 1 -M NCL)"
command echo "SET PASSWORD FOR 'root'@'127.0.0.1' = PASSWORD('${bddpassword}')" | command mysql --user=root
command echo "SET PASSWORD FOR 'root'@'${HOSTNAME}' = PASSWORD('${bddpassword}')" | command mysql --user=root
command mysqladmin -u root password "${bddpassword}"

mysql -u root -p$bddpassword<<EOSQL
CREATE DATABASE owncloud CHARACTER SET utf8;
GRANT ALL PRIVILEGES ON owncloud.* TO 'owncloud'@'localhost' IDENTIFIED BY "$htpassword" WITH GRANT OPTION;
EOSQL
apt-get build-dep calibre -y
apt-get autoremove -y

if [ $? != 0 ]; then
echo "Problème de création de base de données"
exit 5
fi

echo "#############################
#                           #
# Configuration de rTorrent #
#                           #
#############################"

# Création du groupe et de l'utilisateur qui executera rtorrent
echo "$user:$htpassword:4242:4242:$user,,,:/home/$user:/bin/bash" | newusers
if [ $? != 0 ]; then
echo "Problème de création d'utilisateur"
exit 16
fi

# Création des répertoires de fonctionnement de rtorrent
# on créé un lien symbolique vers le répertoire de téléchargement dans la racine www
mkdir /home/$user/downloads
mkdir /home/$user/watch
mkdir /home/$user/.session
ln -s /home/$user/downloads/ /var/www/downloads
chown www-data:www-data /var/www/downloads
chown -R $user:$user /home/$user

# On limite l'accès aux dossiers rtorrent à l'utilisateur rtorrent seul.
chmod -R 755 /home/$user/downloads/
chmod -R 711 /home/$user/.session

echo "directory = /home/$user/downloads
session = /home/$user/.session
download_rate = $downspeed
upload_rate = $upspeed
port_range = 6890-6999
port_random = yes
check_hash = no
use_udp_trackers = yes
schedule = watch_directory,15,15,load_start=/home/$user/watch/*.torrent
schedule = untied_directory,5,5,stop_untied= 
dht = disable
peer_exchange = no
scgi_port = 127.0.0.1:5000
ip = 127.0.0.1
encryption = allow_incoming,require_RC4
" > /home/$user/.rtorrent.rc
if [ $? != 0 ]; then
echo "Problème de configuration de rTorrent"
exit 17
fi

# On s'assure que rtorrent ne tourne pas
killall rtorrent 2> /dev/null

echo "###############################################
#                                             #
# Installation de RuTorrent et de ses plugins #
#                                             #
###############################################"

cd /var/www
svn checkout http://rutorrent.googlecode.com/svn/trunk/rutorrent/
if [ $? != 0 ]; then
echo "Problème de download de rutorrent"
exit 18
fi
cd rutorrent
rm -R plugins
svn checkout http://rutorrent.googlecode.com/svn/trunk/plugins/
if [ $? != 0 ]; then
echo "Problème de download des plugins rutorrent"
exit 19
fi
chown -R www-data:www-data /var/www

echo "##########################
#                        #
# Configuration d'Apache #
#                        #
##########################"

#Arrêt du serveur Apache
service apache2 stop
#Génération du .htpasswd que nous placons dans le dossier /etc/apache2/, à l'abri.
htpasswd -mbc /etc/apache2/.htpasswd $user $htpassword
if [ $? != 0 ]; then
echo "Problème de création de fichier .htpasswd"
exit 20
fi
#Génération des clés de chiffrement
cd /etc/ssl/certs/

echo "
#Creation d'un fichier mot de passe.

"
apg -q -a  0 -n 1 -M NCL > .passwd

echo "
#Génération de notre propre autorité de certification.

"
openssl genrsa -des3 -out ca.key -passout file:.passwd 4096 
if [ $? != 0 ]; then
echo "Problème de d'autorité de certification"
exit 21
fi
openssl req -passin file:.passwd -new -x509 -days 3650 -key ca.key -out ca.crt \
-subj "/C=FR/ST=IDF/L=PARIS/O=42/OU=PROD/CN=$domain"
if [ $? != 0 ]; then
echo "Problème de configuration d'autorité de certification"
exit 22
fi

echo "
#Génération d'une clé serveur et demande de signature.

"
openssl genrsa -passout file:.passwd -des3 -out server.key 4096
if [ $? != 0 ]; then
echo "Problème de création de clé serveur"
exit 23
fi
openssl req -new -key server.key -out server.csr -passin file:.passwd \
-subj "/C=FR/ST=IDF/L=PARIS/O=42/OU=PROD/CN=$domain"
if [ $? != 0 ]; then
echo "Problème de création de certificat serveur"
exit 24
fi

echo "
#Signature du certificat avec l'autorité créée précédemment.

"
openssl x509 -passin file:.passwd -req -days 3650 -in server.csr \
-CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
if [ $? != 0 ]; then
echo "Problème de signature du certificat avec l'autorité"
exit 25
fi

echo "
#Faire un fichier server.key qui n'implique pas une demande de mot de passe d'Apache.

"
openssl rsa -passin file:.passwd -in server.key -out server.key.insecure
if [ $? != 0 ]; then
echo "Problème de configuration de clé serveur"
exit 26
fi

echo "
#Échange des clés.

"
mv server.key server.key.secure
mv server.key.insecure server.key

chmod 400 server.*
chmod 400 .passwd

openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -out $users.crt -keyout $user.key -subj "/C=FR/ST=IDF/L=PARIS/O=42/OU=PROD/CN=$domain"

chmod 400 $user.*
cp $user.crt /home/$user/downloads
cp ca.crt /home/$user/downloads


# Écriture de la configuration Apache
IP=`ifconfig eth0 | grep "inet ad" | cut -f2 -d: | awk '{print $1}'`

echo "#Configuration du module SCGI pour la synchro rTorrent/Rutorrent
SCGIMount /RPC2 127.0.0.1:5000
ServerName http://$domain/

#Redirection http > https
<VirtualHost *:80>
  ServerAdmin admin@kim.sufi
  DocumentRoot /var/www/
  ServerName http://$domain/
  Redirect permanent / https://$domain/
</VirtualHost>

#SSL
<IfModule mod_ssl.c>
<VirtualHost $IP:443>

  ServerAdmin admin@kim.sufi
  DocumentRoot /var/www
  ServerName https://$domain/

  <Directory />
    Options FollowSymLinks
    AllowOverride None
  </Directory>

  <Directory /var/www/>
    Options FollowSymLinks ExecCGI
    AllowOverride All
    Order allow,deny
    allow from All
  </Directory>

  ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
  <Directory \"/usr/lib/cgi-bin\">
    AllowOverride None
    Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
    Order allow,deny
    Allow from all
  </Directory>

  ErrorLog ${APACHE_LOG_DIR}/error.log

  # Possible values include: debug, info, notice, warn, error, crit,
  # alert, emerg.
  LogLevel warn

  CustomLog ${APACHE_LOG_DIR}/ssl_access.log combined

  # Enable/Disable SSL for this virtual host.
  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/server.crt
  SSLCertificateKeyFile /etc/ssl/certs/server.key

  <FilesMatch \".(cgi|shtml|phtml|php)$\">
    SSLOptions +StdEnvVars
  </FilesMatch>
  
  <Directory /usr/lib/cgi-bin>
    SSLOptions +StdEnvVars
  </Directory>
  
    BrowserMatch \"MSIE [2-6]\" \
    nokeepalive ssl-unclean-shutdown \
    downgrade-1.0 force-response-1.0
    # MSIE 7 and newer should be able to use keepalive
    BrowserMatch \"MSIE [7-9]\" ssl-unclean-shutdown
    
  <Directory /var/www>
    Options All
    AllowOverride All
    AuthName \"Private\"
    AuthType Basic
    AuthUserFile /etc/apache2/.htpasswd
    Require user $user
    Order allow,deny
    Allow from All
  </Directory>
  
  <Directory /var/www/downloads>
    Options All
    AllowOverride All
    AuthName \"Private\"
    AuthType Basic
    AuthUserFile /etc/apache2/.htpasswd
    Require user $user
    Order allow,deny
    Allow from All
  </Directory>
  
  </VirtualHost>
  </IfModule>
DirectoryIndex index.html index.php /_h5ai/server/php/index.php" > /etc/apache2/conf.d/$user
if [ $? != 0 ]; then
echo "Problème de configuration Apache"
exit 27
fi

#Activation des différents modules Apache
a2enmod rewrite
if [ $? != 0 ]; then
echo "Problème d'activation de module apache rewrite"
exit 28
fi
a2enmod headers
if [ $? != 0 ]; then
echo "Problème d'activation de module apache headers"
exit 29
fi
a2enmod ssl
if [ $? != 0 ]; then
echo "Problème d'activation de module apache ssl"
exit 30
fi
a2enmod auth_digest
if [ $? != 0 ]; then
echo "Problème d'activation de module apache auth_digest"
exit 31
fi
a2enmod scgi
if [ $? != 0 ]; then
echo "Problème d'activation de module apache scgi"
exit 32
fi

echo "#########################
#                       #
# Installation de _h5ai #
#                       #
#########################"

cd /var/www/
wget http://release.larsjung.de/h5ai/h5ai-0.22.1.zip
if [ $? != 0 ]; then
echo "Problème de download de _H5AI"
exit 33
fi
unzip h5ai-0.22.1.zip
rm h5ai-0.22.1.zip 
rm index.html 

echo "#########################
#                       #
# Configuration du SFTP #
#                       #
#########################"
#On change la configuration du daemon ssh

#On empêche la connexion root, il faudra se connecter avec un
#utilisateur normal et obtenir les privilèges par la suite. (su / sudo)
sed "s/PermitRootLogin/#PermitRootLogin/" /etc/ssh/sshd_config > ssh.config
if [ $? != 0 ]; then
echo "Problème de configuration du SFTP"
exit 37
fi
rm /etc/ssh/sshd_config
mv ssh.config /etc/ssh/sshd_config

echo "
PermitRootLogin no" >> /etc/ssh/sshd_config
echo "###############################
#                             #
# Création du Démon rtorrentd #
#                             #
###############################"

wget https://raw.github.com/synoga/DebianSeedboxInstaller/master/rtorrentd -O /etc/init.d/rtorrent
if [ $? != 0 ]; then
echo "Problème de download du démon rtorrentd"
exit 38
fi
sed "s/XXXUSERXXX/$user/" /etc/init.d/rtorrent > /etc/init.d/rtorrentd
if [ $? != 0 ]; then
echo "Problème de configuration du démon rtorrentd"
exit 39
fi
rm -f /etc/init.d/rtorrent

chmod +x /etc/init.d/rtorrentd
update-rc.d rtorrentd defaults
if [ $? != 0 ]; then
echo "Problème d'activation du démon rtorrentd"
exit 40
fi
echo "###############################
#                             #
#    Configuration du zsh     #
#                             #
###############################"
wget http://formation-debian.via.ecp.fr/fichiers-config/zshrc
if [ $? != 0 ]; then
echo "Problème de download de la conf zsh"
exit 41
fi
wget http://formation-debian.via.ecp.fr/fichiers-config/zshenv
if [ $? != 0 ]; then
echo "Problème de download de la conf zsh"
exit 42
fi
wget http://formation-debian.via.ecp.fr/fichiers-config/zlogin
if [ $? != 0 ]; then
echo "Problème de download de la conf zsh"
exit 43
fi
wget http://formation-debian.via.ecp.fr/fichiers-config/zlogout
if [ $? != 0 ]; then
echo "Problème de download de la conf zsh"
exit 44
fi
wget http://formation-debian.via.ecp.fr/fichiers-config/dir_colors
mv zshrc zshenv zlogin zlogout dir_colors /etc/zsh


echo "#################################
#                               #
#   Installation de Owncloud    #
#                               #
#################################"
 
#On retourne à la maison
cd
mkdir owncloud
cd owncloud
wget http://download.owncloud.org/community/owncloud-5.0.10.tar.bz2
if [ $? != 0 ]; then
echo "Problème de download de owncloud"
exit 45
fi
wget http://download.owncloud.org/community/owncloud-5.0.10.tar.bz2.md5
if [ $? != 0 ]; then
echo "Problème de download de la signature MD5 de owncloud"
exit 46
fi
md5sum -c --status owncloud-5.0.10.tar.bz2.md5 < owncloud-5.0.10.tar.bz2
if [ $? = 0 ]; then
    tar -xjf owncloud-5.0.10.tar.bz2
    cp -r owncloud /var/www
    chown -R www-data:www-data /var/www/
else echo "Téléchargement de Owncloud corrompu, annulation de l'installation" && exit 1
fi



echo "#################################
#                               #
#    Installation de calibre    #
#                               #
#################################"

python -c "import sys; py3 = sys.version_info[0] > 2; u = __import__('urllib.request' if py3 else 'urllib', fromlist=1); exec(u.urlopen('http://status.calibre-ebook.com/linux_installer').read()); main(install_dir='/opt')"
if [ $? != 0 ]; then
echo "Problème d'installation de calibre"
exit 47
fi


echo "###########################
#                         #
# Compilation de rTorrent #
#                         #
###########################"

# Retour à la maison !
cd

# Soyons propres
mkdir sources
cd sources

#wget http://libtorrent.rakshasa.no/downloads/rtorrent-0.9.3.tar.gz
wget http://libtorrent.rakshasa.no/downloads/rtorrent-0.9.3.tar.gz
if [ $? != 0 ]; then
echo "Problème de download du dépot rtorrent"
exit 6
fi
tar xzf rtorrent*

#wget http://libtorrent.rakshasa.no/downloads/libtorrent-0.13.3.tar.gz
wget http://libtorrent.rakshasa.no/downloads/libtorrent-0.13.3.tar.gz
if [ $? != 0 ]; then
echo "Problème de download du dépot libtorrent"
exit 6
fi
tar xzf libtorrent*

#On récupère tout
svn co https://svn.code.sf.net/p/xmlrpc-c/code/advanced xmlrpc-c
if [ $? != 0 ]; then
echo "Problème de download du dépot xmlrpc-c"
exit 6
fi


#XMLRPC
cd xmlrpc-c/
./configure
make && make install
if [ $? != 0 ]; then
echo "Problème de compilation de xmlrpc-c"
exit 11
fi

#libtorrent
cd ../libtorrent*/
./configure
make && make install
if [ $? != 0 ]; then
echo "Problème de compilation de libtorrent"
exit 12
fi

#rtorrent
cd ../rtorrent*/
./configure --with-xmlrpc-c
make && make install
if [ $? != 0 ]; then
echo "Problème de compilation de rtorrent"
exit 13
fi

#On nettoie
cd
rm -Rf sources
if [ $? != 0 ]; then
echo "problème de nettoyage"
exit 14
fi

#Y'a parfois une petite erreur avec la librairie 
ldconfig
if [ $? != 0 ]; then
echo "Problème de configuration des bibliothèques"
exit 15
fi

#On finalise

clear
echo "_H5AI : http://$IP/
Rutorrent : http://$IP/rutorrent/ (login : $user | password : $htpassword)
Owncloud : http://$IP/owncloud/ 

Configuration Owncloud :
Rendez-vous sur http://$IP/owncloud/ et créez votre compte administrateur avec votre login et votre mot de passe puis cliquez sur "Advanced" choisissez une base de données de type MYSQL avec les paramètres suivants : login : owncloud | nom de base : owncloud | mot de passe : $htpassword | hote : localhost

Paramètres SQL : root : $bddpassword

Paramètres FTP :
-Hôte : $IP
-Port : 22
-Protocole : SFTP (SSH File Transfert Protocol)
-Identifiant : $user
-Mot de passe : $htpassword

Le certificat de chiffrement étant autosigné, certains navigateurs vous offriront probablement des avertissements de sécurité. Ignorez-les après avoir vérifié l'url dans la barre d'adresse. De plus, la connexion ssh pour root est désactivée par sécurité, vous pouvez vous connecter avec votre login et votre mot de passe, puis passer root avec la commande su.
Sinon, vous pouvez autoriser manuellement votre navigateur à accepter ce certificat, grâce au fichier /home/$user/ca.crt
"
echo "Terminé."
reboot
if [ $? != 0 ]; then
echo "problème de redémarrage"
exit 51
fi
