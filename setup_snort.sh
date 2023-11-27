#!/bin/bash

# Updating and Upgrading the System
echo "Updating and upgrading the system..."
sudo apt-get update
sudo apt-get upgrade -y

# Installing Snort and Dependencies
echo "Installing Snort and necessary dependencies..."
sudo apt-get install -y snort libpcap-dev libpcre3-dev libdumbnet-dev bison flex make gcc

# Enabling IP Forwarding for Routing Traffic
echo "Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configuring iptables for NFQUEUE and Snort
# Forwarding traffic from eth0 to wlan0 and vice versa through NFQUEUE
echo "Configuring iptables for traffic redirection..."
sudo iptables -I FORWARD -i eth0 -o wlan0 -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -i wlan0 -o eth0 -j NFQUEUE --queue-num 0

# Creating Snort Configuration Directory
echo "Creating configuration directory for Snort..."
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /etc/snort/preproc_rules
sudo mkdir -p /var/log/snort
sudo mkdir -p /usr/local/lib/snort_dynamicrules

# Setting Permissions
echo "Setting permissions for Snort directories..."
sudo chmod -R 5775 /var/log/snort
sudo chmod -R 5775 /etc/snort

# Creating Blank Rule Files
echo "Creating blank rule files..."
sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
sudo touch /etc/snort/rules/local.rules

# Basic Snort Configuration
echo "Configuring Snort..."
sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.backup
sudo sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf
echo "include \$RULE_PATH/local.rules" | sudo tee -a /etc/snort/snort.conf

# Writing Basic Rules
echo "Writing basic Snort rules..."
echo 'alert icmp any any -> $HOME_NET any (msg:"ICMP Detected"; sid:10000001;)' | sudo tee /etc/snort/rules/local.rules
echo 'drop tcp any any -> $HOME_NET 23 (msg:"Telnet access attempt"; sid:10000002;)' | sudo tee -a /etc/snort/rules/local.rules

# Starting Snort in IDS/IPS Mode
echo "Starting Snort in IDS/IPS mode..."
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0:wlan0

echo "Snort IDS/IPS setup completed."

