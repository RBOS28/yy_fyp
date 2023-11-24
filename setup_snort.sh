# Install Snort
apt install snort -y

# Configure Snort rules and variables
cat > /etc/snort/snort.conf <<EOF
# Rule and decoder configuration
config disable_decode_alerts
config disable_tcpopt_experimental_alerts
config disable_tcpopt_obsolete_alerts
config disable_tcpopt_ttcp_alerts
config disable_tcpopt_alerts  

# Home network subnet
ipvar HOME_NET 192.168.1.0/24  

# DNS Servers 
ipvar DNS_SERVERS 192.168.1.1 

# Web Servers
ipvar HTTP_SERVERS 192.168.1.100 

# Rate Limiting 
config event_filter: rate_filter snort_decoder 5, seconds 5, sid 1  

# Include custom rules  
include ./rules/local.rules
EOF

# Create directory for custom rules
mkdir /etc/snort/rules

# Custom rules file
cat >> /etc/snort/rules/local.rules <<EOF
# Alert on outbound SSH brute force attempts
alert tcp \$HOME_NET any -> any 22 (msg:"SSH brute force attempt"; \ 
   flow:to_server,established; threshold: type threshold, track by_src, count 5, seconds 60; sid:10000001;)
EOF

# Set interface and enable service 
sed -i 's/^# config interface:.*/config interface: eth0/' /etc/snort/snort.conf
systemctl enable snort
systemctl start snort
