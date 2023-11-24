# Install OpenVPN
apt install openvpn easy-rsa -y

# Generate keys & certificates
make-cadir /etc/openvpn/keys
cd /etc/openvpn/keys
openvpn --genkey --secret ta.key
openvpn --csr server server.csr 
openvpn --build-ca  
openvpn --build-key-server server
openvpn --build-dh
openvpn --build-client-full client1

# Server config  
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/keys/ca.crt
cert /etc/openvpn/keys/server.crt
key /etc/openvpn/keys/server.key
dh /etc/openvpn/keys/dh.pem  
tls-auth /etc/openvpn/keys/ta.key 0
cipher AES-256-GCM
auth SHA256
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt  

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
explicit-exit-notify 1
persist-key
persist-tun
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 4
mute 20
EOF
