#!/bin/bash

echo ""
echo "----------------------"
echo "Network Configuration"
echo "----------------------"
update_network_config() {
  local interface_name="eth1"
  local address="192.168.16.21/24"
  local gateway="192.168.16.1"
  local dns_server="192.168.16.1"
  local search_domains="home.arpa localdomain"

  if [[ -f /etc/netplan/01-netcfg.yaml ]]; then
    current_config=$(grep -A4 "^\s*ethernets:\s*$interface_name:" /etc/netplan/01-netcfg.yaml)

    if [[ $current_config =~ "$address" && $current_config =~ "$gateway" && $current_config =~ "$dns_server" && $current_config =~ "$search_domains" ]]; then
      echo "Network configuration is already up to date. No changes needed."
    else
      cat <<EOF | sudo tee /etc/netplan/01-netcfg.yaml >/dev/null
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface_name:
      addresses: [$address]
      routes:
        - to: 0.0.0.0/0
          via: $gateway
      nameservers:
        addresses: [$dns_server]
        search: [$search_domains]
EOF

      sudo netplan apply >/dev/null

      existing_entry=$(grep -w "192.168.16.21" /etc/hosts)
      [[ -n "$existing_entry" ]] && sudo sed -i "s/$existing_entry/192.168.16.21\t$(hostname)/" /etc/hosts

      echo "Network configuration updated successfully."
    fi
  fi
}

update_network_config


echo ""
echo "----------------------"
echo "Software Configuration"
echo "----------------------"

# Checking for OpenSSH server presence...
echo "Checking for OpenSSH server..."
if ! command -v sshd &> /dev/null; then
  echo "OpenSSH server is not installed. Proceeding with installation..."
  sudo apt-get update > /dev/null && sudo apt-get install -y openssh-server > /dev/null
  echo "OpenSSH server installation completed."
else
  echo "OpenSSH server is already installed."
fi

# Configuring OpenSSH server for key authentication and disabling password authentication...
echo "Configuring OpenSSH server for key authentication and disabling password authentication..."
if ! grep -qE "^PasswordAuthentication\s*no" /etc/ssh/sshd_config; then
  echo "Password authentication is enabled. Disabling password authentication and enabling key authentication..."
  sudo sed -i '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config
  echo "Key authentication enabled. Password authentication disabled."
  sudo service ssh restart
  echo "OpenSSH server configuration changes applied. Restarting SSH service..."
else
  echo "OpenSSH server is already configured for key authentication and password authentication is disabled."
fi

# Checking for Apache2 presence...
echo "Checking for Apache2..."
if ! command -v apache2 &> /dev/null; then
  echo "Apache2 is not installed. Proceeding with installation..."
  sudo apt-get install -y apache2 > /dev/null
  echo "Apache2 installation completed."
else
  echo "Apache2 is already installed."
fi

# Checking Apache2 configuration for ports 80 and 443...
echo "Checking Apache2 configuration for ports 80 and 443..."
if ! grep -qE "Listen 80" /etc/apache2/ports.conf || ! grep -qE "Listen 443" /etc/apache2/ports.conf; then
  echo "Apache2 is not configured to listen on ports 80 and 443. Modifying configuration..."
  sudo sed -i '/Listen 80/a Listen 443' /etc/apache2/ports.conf
  echo "Apache2 configured to listen on ports 80 and 443."
else
  echo "Apache2 is already configured to listen on ports 80 and 443."
fi

# Checking for Squid presence...
echo "Checking for Squid..."
if ! command -v squid &> /dev/null; then
  echo "Squid is not installed. Proceeding with installation..."
  sudo apt-get install -y squid > /dev/null
  echo "Squid installation completed."
else
  echo "Squid is already installed."
fi

# Checking Squid configuration for port 3128...
echo "Checking Squid configuration for port 3128..."
if ! grep -qE "^http_port\s*3128" /etc/squid/squid.conf; then
  echo "Squid is not configured to listen on port 3128. Modifying configuration..."
  sudo sed -i '/^http_port/s/$/ 3128/' /etc/squid/squid.conf
  echo "Squid configured to listen on port 3128."
  sudo service squid restart
  echo "Squid configuration changes applied. Restarting Squid service..."
else
  echo "Squid is already configured to listen on port 3128."
fi

# Overall software configuration summary...
echo "Software Configuration Summary:"
echo "- OpenSSH server: Installed and configured for key authentication, password authentication disabled."
echo "- Apache2 web server: Installed and configured to listen on ports 80 and 443."
echo "- Squid proxy server: Installed and configured to listen on port 3128."

echo ""
echo "----------------------"
echo "Firewall Configuration"
echo "----------------------"
# Function to check if a port is open
check_port() {
  sudo ss -ntlp | grep -q ":$1 "
}

# Function to add a firewall rule if it does not exist
add_rule() {
  sudo ufw allow $1 comment "$2" &> /dev/null
}

# Install UFW if not installed
command -v ufw &> /dev/null || { echo "UFW is not installed. Installing..." && sudo apt update &> /dev/null && sudo apt install -y ufw &> /dev/null || { echo "Failed to install UFW. Exiting..."; exit 1; } }

# Enable UFW if not enabled
sudo ufw status | grep -q "Status: active" || { echo "Enabling UFW..." && sudo ufw enable &> /dev/null || { echo "Failed to enable UFW. Exiting..."; exit 1; } }

# Define rules in an array
rules=( [22]="SSH" [80]="HTTP" [443]="HTTPS" [3128]="Web Proxy" )

# Apply rules
for port in "${!rules[@]}"; do
  if ! check_port $port; then
    echo "Allowing ${rules[$port]} (Port $port)..."
    add_rule $port "${rules[$port]}" || { echo "Failed to add ${rules[$port]} rule. Exiting..."; exit 1; }
  else
    echo "${rules[$port]} (Port $port) is already allowed."
  fi
done
echo "Firewall setup complete"

echo ""
echo "----------------------"
echo "User Accounts Setup"
echo "----------------------"
users=("dennis" "aubrey" "captain" "snibbles" "brownie" "scooter" "sandy" "perrier" "cindy" "tiger" "yoda")

# Function to create a user account
create_user() {
  local user=$1

  if id -u "$user" >/dev/null 2>&1; then
    printf "User '%s' already exists. Skipping...\n" "$user"
  else
    printf "Creating user '%s'...\n" "$user"
    sudo useradd -m -d /home/$user -s /bin/bash "$user"

    printf "Generating SSH keys for user '%s'...\n" "$user"
    sudo mkdir -p /home/$user/.ssh
    sudo touch /home/$user/.ssh/authorized_keys
    sudo chmod 700 /home/$user/.ssh
    sudo chmod 600 /home/$user/.ssh/authorized_keys

    for key_type in rsa ed25519; do
      sudo ssh-keygen -t $key_type -f /home/$user/.ssh/id_$key_type -q -N ""
      sudo chmod 600 /home/$user/.ssh/id_$key_type
      sudo cat /home/$user/.ssh/id_$key_type.pub >> /home/$user/.ssh/authorized_keys
    done

    if [[ "$user" == "dennis" ]]; then
      printf "Granting sudo access to user '%s'...\n" "$user"
      sudo usermod -aG sudo "$user"
    fi

    printf "User '%s' created successfully.\n" "$user"
  fi
}

# Create user accounts
for user in "${users[@]}"; do
  create_user "$user"
done

# Add an additional SSH public key to dennis's authorized_keys file
printf "Adding additional SSH public key to user 'dennis'...\n"
sudo echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm" >> /home/dennis/.ssh/authorized_keys

echo "All user accounts created and configured successfully."
	
