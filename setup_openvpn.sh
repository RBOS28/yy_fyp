# Install OpenVPN 
apt install openvpn easy-rsa -y

# Generate PKI keys & certificates
make-cadir /etc/openvpn/keys
cd /etc/openvpn/keys
openvpn --genkey --secret ta.key
openvpn --csr server ../server.csr
openvpn --build-ca --batch
openvpn --dh dh.pem
openvpn --build-server-full server nopass
openvpn --build-client-full client1 nopass 

# Server Config
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/keys/ca.crt
cert /etc/openvpn/keys/server.crt  
key /etc/openvpn/keys/server.key
dh /etc/openvpn/keys/dh.pem 
tls-auth /etc/openvpn/keys/ta.key
cipher AES-256-GCM
auth SHA512
ifconfig 10.9.0.1 255.255.255.0
push "redirect-gateway def1 bypass-dhcp" 
client-to-client
duplicate-cn
keepalive 10 120
comp-lzo
user openvpn
group openvpn
persist-key
persist-tun
verb 3
EOF

# IPtables Rules  
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 
iptables -A FORWARD -s 10.9.0.0/24 -j ACCEPT

# Save IPtables Rules
iptables-save > /etc/iptables.rules
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Start OpenVPN
systemctl start openvpn
systemctl enable openvpn
