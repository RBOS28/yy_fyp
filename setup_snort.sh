# Install Snort 
apt install snort barnyard2 mysql-server apache2 php libapache2-mod-php php-mysql -y

# Configure MySQL database
mysql -e "CREATE DATABASE snort;"
mysql -e "CREATE USER 'snort'@'localhost' IDENTIFIED BY 'password';"  
mysql -e "GRANT ALL ON snort.* TO 'snort'@'localhost';"

# Configure Barnyard2
cat > /etc/snort/barnyard2.conf << EOF
config daemon
config interface: eth0
config logdir: /var/log/snort
output database: log, mysql, user=snort password=password dbname=snort host=localhost  
EOF

# Configure Snort rules
cat > /etc/snort/snort.conf << EOF
ipvar HOME_NET 192.168.20.0/24
rulepath ./rules
include classification.config
include reference.config
include $RULE_PATH/snortrules-snapshot-29131.tar
include $RULE_PATH/app-detect.rules
EOF

# Pull community rules
wget https://www.snort.org/rules/snortrules-snapshot-29131.tar?o=f -O /etc/snort/rules/snortrules-snapshot-29131.tar

# Create IPS drop rules  
echo "drop tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg: \"Block SSH Bruteforce\"; sid:10000001;)" > /etc/snort/rules/local.rules  

# Start services
systemctl enable mysql barnyard2 snort apache2
systemctl start mysql barnyard2 snort apache2
