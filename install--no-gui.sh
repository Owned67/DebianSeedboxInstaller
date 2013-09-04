# /bin/bash

#On commence par vérifier que le script est lancé en tant que root
if [ `whoami` != "root" ]; then 
echo "*********************************************************************************
Vous devez avoir les privilèges super-utilisateur (root) pour exécuter ce script.
*********************************************************************************"
exit 1
fi 

#On configure les locales
rm -f /etc/locale.gen
echo "fr_FR.UTF-8 UTF-8
fr_FR.UTF-8@euro UTF-8
en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen

#On demande un login et un pass pour la SeedBox
user=$1
htpassword=$2
domain=$3

user=synoga
htpassword=azerty
domain=chenoute.info

#On peut donc mettre à jour le système et installer les paquets nécessaires.
apt-get update -y && apt-get upgrade -y
apt-get install -y locale
apt-get install -y apache2 
apt-get install -y apache2-doc 
apt-get install -y apache2-mpm-prefork 
apt-get install -y apache2-utils 
apt-get install -y libexpat1 
apt-get install -y ssl-cert 
apt-get install -y libapache2-mod-php5 
apt-get install -y php5 
apt-get install -y php5-common 
apt-get install -y php5-curl 
apt-get install -y php5-dev 
apt-get install -y php5-gd 
apt-get install -y php5-idn 
apt-get install -y php-pear 
apt-get install -y php5-imagick 
apt-get install -y php5-imap 
apt-get install -y php5-json 
apt-get install -y php5-mcrypt 
apt-get install -y php5-memcache 
apt-get install -y php5-mhash 
apt-get install -y php5-ming 
apt-get install -y php5-mysql 
apt-get install -y php5-ps 
apt-get install -y php5spell 
apt-get install -y php5-recode 
apt-get install -y php5-snmp 
apt-get install -y php5-sqlite 
apt-get install -y php5-tidy 
apt-get install -y php5-xmlrpc 
apt-get install -y php5-xsl 
apt-get install -y libapache2-mod-scgi 
apt-get install -y build-essential 
apt-get install -y make 
apt-get install -y gcc 
apt-get install -y autoconf 
apt-get install -y curl 
apt-get install -y libcurl3 
apt-get install -y libcurl4-openssl-dev 
apt-get install -y zip 
apt-get install -y unzip 
apt-get install -y libc6-dev 
apt-get install -y linux-kernel-headers 
apt-get install -y diffutils 
apt-get install -y wget 
apt-get install -y bzip2 
apt-get install -y screen 
apt-get install -y ffmpeg 
apt-get install -y libcppunit-dev 
apt-get install -y libncurses5-dev 
apt-get install -y libncursesw5-dev 
apt-get install -y subversion 
apt-get install -y libsigc++ 
apt-get install -y imagemagick 
apt-get install -y zsh 
apt-get install -y git 
apt-get install -y openssl 
apt-get install -y unrar-free
apt-get install -y mp3info 
apt-get install -y libcurl3-dev 
apt-get install -y mysql-server

#Installation de rTorrent
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

#On récupère tout
svn co https://svn.code.sf.net/p/xmlrpc-c/code/advanced xmlrpc-c
wget http://libtorrent.rakshasa.no/downloads/libtorrent-0.13.2.tar.gz
wget http://libtorrent.rakshasa.no/downloads/rtorrent-0.9.2.tar.gz

#On extrait !
tar xvzf libtorrent-0.13.2.tar.gz
tar xvzf rtorrent-0.9.2.tar.gz
rm *.tar.gz

#XMLRPC
cd xmlrpc-c/
./configure
make && make install

#libtorrent
cd ../libtorrent-0.13.2/
./configure
make && make install

#rtorrent
cd ../rtorrent-0.9.2/
./autogen.sh 
./configure --with-xmlrpc-c
make && make install

#On nettoie
cd
rm -Rf sources

#Y'a parfois une petite erreur avec la librairie 
ldconfig

echo "#############################
#                           #
# Configuration de rTorrent #
#                           #
#############################"

# Création du groupe et de l'utilisateur qui executera rtorrent
echo "$user:$htpassword:4242:4242:$user,,,:/home/$user:/bin/bash" | newusers

# Création des répertoires de fonctionnement de rtorrent
# on créé un lien symbolique vers le répertoire de téléchargement dans la racine www
mkdir /home/$user/downloads
mkdir /home/$user/watch
mkdir /home/$user/.session
ln -s /home/$user/downloads /var/www/downloads
chown www-data:www-data /var/www/downloads
chown -R $user:$user /home/$user

# On limite l'accès aux dossiers rtorrent à l'utilisateur rtorrent seul.
chmod -R 755 /home/$user/downloads/
chmod -R 711 /home/$user/.session

#On écrit le fichier de configuration .rtorrent.rc en fonction du paramètre de chiffrement obtenu plus haut.

echo "directory = /home/$user/downloads
session = /home/$user/.session
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

# On s'assure que rtorrent ne tourne pas
killall rtorrent 2> /dev/null
echo "###############################################
#                                             #
# Installation de RuTorrent et de ses plugins #
#                                             #
###############################################"

cd /var/www
svn checkout http://rutorrent.googlecode.com/svn/trunk/rutorrent/
cd rutorrent
rm -R plugins
svn checkout http://rutorrent.googlecode.com/svn/trunk/plugins/
chown -R www-data:www-data /var/www

echo "##########################
#                        #
# Configuration d'Apache #
#                        #
##########################"

#Arrêt du serveur Apache
service apache2 stop
#Génération du .htpasswd que nous placons dans le dossier etc/apache2, à l'abri.
htpasswd -mbc /etc/apache2/.htpasswd $user $htpassword
#Génération des clés de chiffrement
cd /etc/ssl/certs/

echo "
#Creation d'un fichier mot de passe.

"
echo 6ec728db6df7 > .passwd

echo "
#Génération de notre propre autorité de certification.

"
openssl genrsa -des3 -out ca.key -passout file:.passwd 4096 
openssl req -passin file:.passwd -new -x509 -days 3650 -key ca.key -out ca.crt \
-subj "/C=FR/ST=IDF/L=PARIS/O=42/OU=PROD/CN=$domain"

echo "
#Génération d'une clé serveur et demande de signature.

"
openssl genrsa -passout file:.passwd -des3 -out server.key 4096
openssl req -new -key server.key -out server.csr -passin file:.passwd \
-subj "/C=FR/ST=IDF/L=PARIS/O=42/OU=PROD/CN=$domain"

echo "
#Signature du certificat avec l'autorité créée précédemment.

"
openssl x509 -passin file:.passwd -req -days 3650 -in server.csr \
-CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

echo "
#Faire un fichier server.key qui n'implique pas une demande de mot de passe d'Apache.

"
openssl rsa -passin file:.passwd -in server.key -out server.key.insecure

echo "
#Échange des clés.

"
mv server.key server.key.secure
mv server.key.insecure server.key

chmod 400 server.*
chmod 400 .passwd


# Écriture de la configuration Apache
IP=`ifconfig eth0 | grep "inet ad" | cut -f2 -d: | awk '{print $1}'`

echo '#Configuration du module SCGI pour la synchro rTorrent/Rutorrent
SCGIMount /RPC2 127.0.0.1:5000
ServerName http://$IP/

#Redirection http > https
<VirtualHost $IP:80>
  ServerAdmin admin@kim.sufi
  DocumentRoot /var/www/
  ServerName http://$IP/
  Redirect permanent / https://$IP/
</VirtualHost>

#SSL
<IfModule mod_ssl.c>
<VirtualHost $IP:443>

  ServerAdmin admin@kim.sufi
  DocumentRoot /var/www
  ServerName https://$IP

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
DirectoryIndex index.html index.php /_h5ai/server/php/index.php' > /etc/apache2/conf.d/$user

#Activation des différents modules Apache
a2enmod rewrite
a2enmod ssl
a2enmod auth_digest
a2enmod scgi

echo "#########################
#                       #
# Installation de _h5ai #
#                       #
#########################"

cd /var/www/
wget http://release.larsjung.de/h5ai/h5ai-0.22.1.zip
unzip h5ai-0.22.1.zip
rm h5ai-0.22.1.zip 
rm index.html 

echo "#############################
#                           #
# Installation de Mediainfo #
#                           #
#############################"

cd
mkdir mediainfo
cd mediainfo

# On récupère !
wget http://mediaarea.net/download/binary/libzen0/0.4.28/libzen0_0.4.28-1_amd64.Debian_6.0.deb
wget http://mediaarea.net/download/binary/libmediainfo0/0.7.61/libmediainfo0_0.7.61-1_amd64.Debian_6.0.deb
wget http://mediaarea.net/download/binary/mediainfo/0.7.61/mediainfo_0.7.61-1_amd64.Debian_6.0.deb

# On installe !
dpkg -i *.deb

# On clean !
cd && rm -Rf mediainfo


echo "#########################
#                       #
# Configuration du SFTP #
#                       #
#########################"
#On change la configuration du daemon ssh

#On empêche la connexion root, il faudra se connecter avec un
#utilisateur normal et obtenir les privilèges par la suite. (su / sudo)
sed "s/PermitRootLogin/#PermitRootLogin/" /etc/ssh/sshd_config > ssh.config
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
sed "s/XXXUSERXXX/$user/" /etc/init.d/rtorrent > /etc/init.d/rtorrentd

chmod +x /etc/init.d/rtorrentd
update-rc.d rtorrentd defaults

echo "###############################
#                             #
#    Configuration du zsh     #
#                             #
###############################"
wget http://formation-debian.via.ecp.fr/fichiers-config/zshrc
wget http://formation-debian.via.ecp.fr/fichiers-config/zshenv
wget http://formation-debian.via.ecp.fr/fichiers-config/zlogin
wget http://formation-debian.via.ecp.fr/fichiers-config/zlogout
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
wget http://download.owncloud.org/community/owncloud-5.0.10.tar.bz2.md5
md5sum -c --status owncloud-5.0.10.tar.bz2.md5 < owncloud-5.0.10.tar.bz2
if [ $? = 0 ]
    then instruction(s)
else echo "Téléchargement de Owncloud corrompu, annulation de l'installation" && exit 1
fi



echo "#################################
#                               #
#    Installation de calibre    #
#                               #
#################################"
echo "################################
#                              #
#    Démarrage des services    #
#                              #
################################"
#On finalise

#Démarrage du démon rtorrent
service rtorrentd start

#Redémarrage d'Apache
service apache2 start

#Puis on redémarre le démon ssh
service ssh restart

echo "Pour accéder à votre Seedbox : http://$IP/
Votre login est : $user
Votre mot de passe est celui donné en début d'installation, j'espère que vous l'avez noté.

Paramètres FTP :
-Hôte : $IP
-Port : 22
-Protocole : SFTP (SSH File Transfert Protocol)
-Identifiant : $user
-Mot de passe : Je vous laisse deviner.

Le certificat de chiffrement étant autosigné, certains navigateurs vous offriront probablement des avertissements de sécurité. Ignorez-les après avoir vérifié l'url dans la barre d'adresse. De plus, la connexion ssh pour root est désactivée par sécurité, vous pouvez vous connecter avec votre login et votre mot de passe, puis passer root avec la commande su."
echo "Terminé"
