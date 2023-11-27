#!/bin/bash

# Update system and install OpenVPN and Easy-RSA
echo "Updating system and installing OpenVPN and Easy-RSA..."
apt-get update
apt-get install -y openvpn easy-rsa

# Make a directory for Easy-RSA keys and build the CA
echo "Setting up Easy-RSA..."
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Initialize the PKI (Public Key Infrastructure)
./easyrsa init-pki

# Build the Certificate Authority (CA)
echo "Building the CA..."
./easyrsa build-ca nopass

# Generate Diffie-Hellman parameters
echo "Generating Diffie-Hellman parameters..."
./easyrsa gen-dh

# Generate server key and certificate
echo "Generating server key and certificate..."
./easyrsa build-server-full server nopass

# Generate client key and certificate
echo "Generating client key and certificate..."
./easyrsa build-client-full client1 nopass

# Generate HMAC signature to strengthen the server's TLS integrity verification capabilities
openvpn --genkey --secret /etc/openvpn/ta.key

# Move all generated files to /etc/openvpn
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn

# Server Configuration
echo "Configuring OpenVPN server..."
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF

# Enable and start the OpenVPN service
echo "Enabling and starting OpenVPN service..."
systemctl enable openvpn@server
systemctl start openvpn@server

echo "OpenVPN server setup is complete."

