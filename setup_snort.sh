#!/bin/bash

# Define constants
SNORT_CONF="/etc/snort/snort.conf"
SNORT_RULES_DIR="/etc/snort/rules"
SNORT_LOG_DIR="/var/log/snort"
SNORT_DYNAMIC_RULES_DIR="/usr/local/lib/snort_dynamicrules"

# Step 1: Update and Upgrade the System
echo "Updating and upgrading the system..."
sudo apt-get update
sudo apt-get upgrade -y

# Step 2: Install Snort and Dependencies
echo "Installing Snort and necessary dependencies..."
sudo apt-get install -y snort libpcap-dev libpcre3-dev libdumbnet-dev bison flex make gcc

# Step 3: Enabling IP Forwarding for Routing Traffic
echo "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# Step 4: Configure iptables for Traffic Redirection
echo "Configuring iptables for traffic redirection..."
sudo iptables -I FORWARD -i eth0 -o wlan0 -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -i wlan0 -o eth0 -j NFQUEUE --queue-num 0

# Step 5: Setting Up Snort Configuration and Rules
echo "Setting up Snort configuration and rules directories..."
sudo mkdir -p $SNORT_RULES_DIR
sudo mkdir -p $SNORT_LOG_DIR
sudo mkdir -p $SNORT_DYNAMIC_RULES_DIR

# Setting Permissions
sudo chmod -R 5775 $SNORT_LOG_DIR
sudo chmod -R 5775 $SNORT_CONF

# Creating Blank Rule Files
sudo touch $SNORT_RULES_DIR/local.rules
sudo touch $SNORT_RULES_DIR/white_list.rules
sudo touch $SNORT_RULES_DIR/black_list.rules

# Backup Snort Config
sudo cp $SNORT_CONF $SNORT_CONF.backup

# Basic Snort Configuration Adjustments
echo "Configuring basic Snort settings..."
sudo sed -i 's/include \$RULE_PATH/#include \$RULE_PATH/' $SNORT_CONF
echo "include \$RULE_PATH/local.rules" | sudo tee -a $SNORT_CONF

# Writing Basic Detection and Prevention Rules
echo "Writing basic Snort detection and prevention rules..."
echo 'alert icmp any any -> $HOME_NET any (msg:"ICMP Detected"; sid:1000001;)' | sudo tee -a $SNORT_RULES_DIR/local.rules
echo 'drop tcp any any -> $HOME_NET 23 (msg:"Telnet access attempt"; sid:1000002;)' | sudo tee -a $SNORT_RULES_DIR/local.rules

# Step 6: Starting Snort in IDS/IPS Mode
echo "Starting Snort in IDS/IPS mode..."
sudo snort -A console -q -c $SNORT_CONF -i eth0:wlan0

echo "Snort IDS/IPS setup is complete."

