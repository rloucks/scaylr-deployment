#!/bin/bash

#######################################
# SentinelOne Collector (Scalyr Agent) Complete Setup Script
# Supports: Arch, RHEL, Fedora, Ubuntu, Debian
# Features: OS detection, installation, hardening, read-only user
# Official SentinelOne Installation Process
#######################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
OS_TYPE=""
OS_VERSION=""
PACKAGE_MANAGER=""
USERNAME="scalyr"
SCALYR_API_KEY=""
SCALYR_SERVER_URL=""
SCALYR_CONFIG="/etc/scalyr-agent-2/agent.json"
SCALYR_SERVICE="scalyr-agent-2"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}=========================================="
    echo -e "$1"
    echo -e "==========================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    print_info "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
        
        case $OS_NAME in
            arch|manjaro)
                OS_TYPE="arch"
                PACKAGE_MANAGER="pacman"
                ;;
            fedora)
                OS_TYPE="fedora"
                PACKAGE_MANAGER="dnf"
                ;;
            rhel|centos|rocky|almalinux)
                OS_TYPE="rhel"
                PACKAGE_MANAGER="yum"
                if command -v dnf &>/dev/null; then
                    PACKAGE_MANAGER="dnf"
                fi
                ;;
            ubuntu)
                OS_TYPE="ubuntu"
                PACKAGE_MANAGER="apt"
                ;;
            debian)
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
                ;;
            *)
                print_error "Unsupported OS: $OS_NAME"
                exit 1
                ;;
        esac
        
        print_success "Detected: $NAME $VERSION_ID ($OS_TYPE)"
    else
        print_error "Cannot detect OS. /etc/os-release not found"
        exit 1
    fi
}

# Function to ask for OS confirmation
confirm_os() {
    echo ""
    print_header "Operating System Selection"
    echo "Auto-detected OS: $OS_TYPE"
    echo ""
    echo "Supported distributions:"
    echo "  1) Arch Linux"
    echo "  2) RHEL/CentOS/Rocky/AlmaLinux"
    echo "  3) Fedora"
    echo "  4) Ubuntu"
    echo "  5) Debian"
    echo ""
    read -p "Is the detection correct? (y/n) [y]: " OS_CONFIRM
    OS_CONFIRM=${OS_CONFIRM:-y}
    
    if [[ ! "$OS_CONFIRM" =~ ^[Yy]$ ]]; then
        echo ""
        read -p "Select your OS (1-5): " OS_CHOICE
        case $OS_CHOICE in
            1)
                OS_TYPE="arch"
                PACKAGE_MANAGER="pacman"
                ;;
            2)
                OS_TYPE="rhel"
                PACKAGE_MANAGER="yum"
                ;;
            3)
                OS_TYPE="fedora"
                PACKAGE_MANAGER="dnf"
                ;;
            4)
                OS_TYPE="ubuntu"
                PACKAGE_MANAGER="apt"
                ;;
            5)
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
                ;;
            *)
                print_error "Invalid selection"
                exit 1
                ;;
        esac
        print_success "OS set to: $OS_TYPE"
    fi
}

# Function to check if user exists
user_exists() {
    id "$1" &>/dev/null
}

# Function to check if group exists
group_exists() {
    getent group "$1" &>/dev/null
}

# Function to install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    
    case $OS_TYPE in
        arch)
            pacman -Sy --noconfirm --needed wget curl acl python python-pip
            ;;
        fedora|rhel)
            $PACKAGE_MANAGER install -y wget curl acl python3 python3-pip
            ;;
        ubuntu|debian)
            apt-get update
            apt-get install -y wget curl acl python3 python3-pip
            ;;
    esac
    
    print_success "Dependencies installed"
}

# Function to check if Scalyr is installed
is_scalyr_installed() {
    if command -v scalyr-agent-2 &>/dev/null || [[ -f /usr/share/scalyr-agent-2/bin/scalyr-agent-2 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to install Scalyr agent
install_scalyr() {
    print_info "Installing SentinelOne Collector (Scalyr Agent)..."
    
    if is_scalyr_installed; then
        print_warning "SentinelOne Collector is already installed"
        read -p "Do you want to reinstall? (y/n) [n]: " REINSTALL
        REINSTALL=${REINSTALL:-n}
        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Download official SentinelOne install-agent.sh script
    print_info "Downloading official SentinelOne Collector installer..."
    curl -sO https://www.scalyr.com/install-agent.sh
    
    if [[ ! -f install-agent.sh ]]; then
        print_error "Failed to download SentinelOne Collector installation script"
        exit 1
    fi
    
    # Validate we have the API key
    if [[ -z "$SCALYR_API_KEY" ]]; then
        print_error "API key must be set before installation"
        exit 1
    fi
    
    # Run official installation script with API key
    # This is the official SentinelOne method
    print_info "Running SentinelOne Collector installation with API key..."
    bash ./install-agent.sh --set-api-key "$SCALYR_API_KEY" || {
        print_error "SentinelOne Collector installation failed"
        exit 1
    }
    
    # Clean up installation script
    rm -f install-agent.sh
    
    print_success "SentinelOne Collector installed"
}

# Function to create read-only user
create_readonly_user() {
    print_info "Creating read-only user: $USERNAME"
    
    if user_exists "$USERNAME"; then
        print_warning "User '$USERNAME' already exists"
        return 0
    fi
    
    # Create system user with no login
    useradd -r -s /usr/sbin/nologin -M "$USERNAME" 2>/dev/null || useradd -r -s /sbin/nologin -M "$USERNAME"
    
    # Lock the password
    passwd -l "$USERNAME" &>/dev/null
    
    print_success "User '$USERNAME' created and locked"
}

# Function to configure log access
configure_log_access() {
    print_info "Configuring log access for $USERNAME..."
    
    # Group-based access
    local groups_to_add=()
    
    # Add to systemd-journal if exists
    if group_exists "systemd-journal"; then
        groups_to_add+=("systemd-journal")
    fi
    
    # Add to adm group (Ubuntu/Debian)
    if group_exists "adm"; then
        groups_to_add+=("adm")
    fi
    
    # Add to appropriate groups based on OS
    case $OS_TYPE in
        arch)
            group_exists "log" && groups_to_add+=("log")
            ;;
        fedora|rhel)
            # On RHEL/Fedora, often need root group for some logs
            groups_to_add+=("root")
            ;;
        ubuntu|debian)
            group_exists "syslog" && groups_to_add+=("syslog")
            ;;
    esac
    
    # Add user to groups
    for grp in "${groups_to_add[@]}"; do
        usermod -aG "$grp" "$USERNAME"
        print_success "Added to group: $grp"
    done
    
    # ACL-based access
    print_info "Setting ACLs on /var/log..."
    if command -v setfacl &>/dev/null; then
        setfacl -R -m u:"$USERNAME":rX /var/log 2>/dev/null || print_warning "Some ACLs may have failed"
        setfacl -R -d -m u:"$USERNAME":rX /var/log 2>/dev/null || print_warning "Some default ACLs may have failed"
        print_success "ACLs configured"
    else
        print_warning "setfacl not available, skipping ACL configuration"
    fi
}

# Function to configure Scalyr agent
configure_scalyr() {
    print_info "Configuring SentinelOne Collector..."
    
    # The API key was already set during installation with --set-api-key
    # Now we need to set the scalyr-server URL
    
    if [[ -z "$SCALYR_SERVER_URL" ]]; then
        print_error "SentinelOne server URL must be set"
        exit 1
    fi
    
    print_info "Setting SentinelOne Data Lake server URL..."
    scalyr-agent-2-config --set-scalyr-server "$SCALYR_SERVER_URL" || {
        print_error "Failed to set scalyr-server URL"
        exit 1
    }
    
    print_success "Server URL configured: $SCALYR_SERVER_URL"
    
    # Backup existing config
    if [[ -f "$SCALYR_CONFIG" ]]; then
        cp "$SCALYR_CONFIG" "${SCALYR_CONFIG}.backup.$(date +%Y%m%d%H%M%S)"
        print_info "Backed up existing configuration"
    fi
    
    # Add log file monitoring configuration using Python
    print_info "Configuring log file monitoring..."
    
    python3 -c "
import json
import os

config_file = '$SCALYR_CONFIG'
if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        content = f.read()
        # Remove comments for parsing
        lines = []
        for line in content.split('\n'):
            # Keep line if it doesn't start with //
            stripped = line.strip()
            if not stripped.startswith('//'):
                lines.append(line)
        clean_content = '\n'.join(lines)
        try:
            config = json.loads(clean_content)
        except:
            config = {}
else:
    config = {}

# Ensure server_attributes exists
if 'server_attributes' not in config:
    config['server_attributes'] = {}
if 'serverHost' not in config['server_attributes']:
    config['server_attributes']['serverHost'] = '$(hostname)'

# Add log monitoring
if 'logs' not in config:
    config['logs'] = []

# Add common system logs if not already present
log_paths = [
    {'path': '/var/log/messages*', 'attributes': {'parser': 'systemLog'}},
    {'path': '/var/log/syslog*', 'attributes': {'parser': 'systemLog'}},
    {'path': '/var/log/secure*', 'attributes': {'parser': 'systemLog'}},
    {'path': '/var/log/auth.log*', 'attributes': {'parser': 'systemLog'}}
]

existing_paths = [log.get('path') for log in config['logs']]
for log_path in log_paths:
    if log_path['path'] not in existing_paths:
        config['logs'].append(log_path)

# Write back to file with proper JSON formatting
with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)
    
print('Log monitoring configured')
" 2>/dev/null || {
        print_warning "Python configuration update failed, logs may need manual configuration"
    }
    
    # Set proper permissions on config files
    if [[ -f "$SCALYR_CONFIG" ]]; then
        chown "$USERNAME":"$USERNAME" "$SCALYR_CONFIG" 2>/dev/null || chown "$USERNAME" "$SCALYR_CONFIG"
        chmod 640 "$SCALYR_CONFIG"
    fi
    
    # Set permissions on config directory
    if [[ -d "$(dirname "$SCALYR_CONFIG")" ]]; then
        chown -R "$USERNAME":"$USERNAME" "$(dirname "$SCALYR_CONFIG")" 2>/dev/null || chown -R "$USERNAME" "$(dirname "$SCALYR_CONFIG")"
    fi
    
    # Configure agent to run as specified user in agent.d directory
    local agent_d_dir="/etc/scalyr-agent-2/agent.d"
    mkdir -p "$agent_d_dir"
    
    cat > "$agent_d_dir/user.json" <<EOF
{
  "user": "$USERNAME"
}
EOF
    
    chown -R "$USERNAME":"$USERNAME" "$agent_d_dir" 2>/dev/null || chown -R "$USERNAME" "$agent_d_dir"
    
    print_success "SentinelOne Collector configuration complete"
}

# Function to harden Scalyr installation
harden_scalyr() {
    print_header "Hardening Scalyr Installation"
    
    local config_dir="$(dirname "$SCALYR_CONFIG")"
    local data_dir="/var/lib/scalyr-agent-2"
    local log_dir="/var/log/scalyr-agent-2"
    
    # 1. Restrict file permissions
    print_info "Setting restrictive file permissions..."
    chmod 750 "$config_dir"
    chmod 640 "$SCALYR_CONFIG"
    
    if [[ -d "$data_dir" ]]; then
        chown -R "$USERNAME":"$USERNAME" "$data_dir" 2>/dev/null || chown -R "$USERNAME" "$data_dir"
        chmod 750 "$data_dir"
        print_success "Secured data directory"
    fi
    
    if [[ -d "$log_dir" ]]; then
        chown -R "$USERNAME":"$USERNAME" "$log_dir" 2>/dev/null || chown -R "$USERNAME" "$log_dir"
        chmod 750 "$log_dir"
        print_success "Secured log directory"
    fi
    
    # 2. Configure systemd service hardening
    print_info "Hardening systemd service..."
    local service_file="/etc/systemd/system/$SCALYR_SERVICE.service.d/hardening.conf"
    mkdir -p "$(dirname "$service_file")"
    
    cat > "$service_file" <<EOF
[Service]
# Run as non-root user
User=$USERNAME
Group=$USERNAME

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/scalyr-agent-2 /var/log/scalyr-agent-2
ReadOnlyPaths=/var/log

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=10.0.0.0/8
IPAddressAllow=172.16.0.0/12
IPAddressAllow=192.168.0.0/16

# Capability restrictions
CapabilityBoundingSet=
AmbientCapabilities=

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount

# Device access
DevicePolicy=closed

# Kernel restrictions
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Restrict namespaces
RestrictNamespaces=true

# Lock down personality
LockPersonality=true

# Memory protection
MemoryDenyWriteExecute=true
RestrictRealtime=true

# Remove unnecessary privileges
RestrictSUIDSGID=true
RemoveIPC=true
PrivateMounts=true
EOF
    
    systemctl daemon-reload
    print_success "Systemd service hardened"
    
    # 3. Configure AppArmor/SELinux if available
    if command -v aa-status &>/dev/null; then
        print_info "AppArmor detected - consider creating a profile"
        print_warning "AppArmor profile creation requires manual configuration"
    fi
    
    if command -v getenforce &>/dev/null; then
        if [[ "$(getenforce)" != "Disabled" ]]; then
            print_info "SELinux detected - configuring contexts..."
            
            # Set SELinux contexts
            if command -v semanage &>/dev/null && command -v restorecon &>/dev/null; then
                semanage fcontext -a -t var_log_t "$log_dir(/.*)?" 2>/dev/null || true
                semanage fcontext -a -t etc_t "$config_dir(/.*)?" 2>/dev/null || true
                restorecon -R "$log_dir" 2>/dev/null || true
                restorecon -R "$config_dir" 2>/dev/null || true
                print_success "SELinux contexts configured"
            else
                print_warning "SELinux tools not available for automatic configuration"
            fi
        fi
    fi
    
    # 4. Setup log rotation
    print_info "Configuring log rotation..."
    cat > /etc/logrotate.d/scalyr-agent-2 <<EOF
$log_dir/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $USERNAME $USERNAME
}
EOF
    print_success "Log rotation configured"
    
    # 5. Restrict network access (firewall)
    print_info "Configuring firewall rules..."
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        # Allow only outbound HTTPS to Scalyr
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m owner --uid-owner $(id -u "$USERNAME") -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        print_success "Firewall rules configured"
    elif command -v ufw &>/dev/null; then
        # UFW on Ubuntu/Debian
        ufw allow out from any to any port 443 proto tcp 2>/dev/null || true
        print_success "UFW rules configured"
    else
        print_warning "No supported firewall detected, skipping firewall configuration"
    fi
    
    # 6. Audit logging
    if [[ -f /etc/audit/rules.d/audit.rules ]] || [[ -f /etc/audit/audit.rules ]]; then
        print_info "Configuring audit rules..."
        local audit_rules_file="/etc/audit/rules.d/scalyr.rules"
        cat > "$audit_rules_file" <<EOF
# Monitor Scalyr configuration changes
-w $SCALYR_CONFIG -p wa -k scalyr_config
-w $config_dir -p wa -k scalyr_config
-w $data_dir -p wa -k scalyr_data
EOF
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
        print_success "Audit rules configured"
    fi
    
    print_success "Hardening complete"
}

# Function to verify installation
verify_installation() {
    print_header "Verifying Installation"
    
    local all_good=true
    
    # Check if user exists
    echo -n "Checking user '$USERNAME'... "
    if user_exists "$USERNAME"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        all_good=false
    fi
    
    # Check if Scalyr is installed
    echo -n "Checking Scalyr installation... "
    if is_scalyr_installed; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        all_good=false
    fi
    
    # Check configuration file
    echo -n "Checking configuration file... "
    if [[ -f "$SCALYR_CONFIG" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        all_good=false
    fi
    
    # Test log access
    echo -n "Testing log access... "
    local test_passed=false
    for logfile in /var/log/messages /var/log/syslog /var/log/auth.log; do
        if [[ -f "$logfile" ]]; then
            if sudo -u "$USERNAME" cat "$logfile" &>/dev/null; then
                test_passed=true
                break
            fi
        fi
    done
    
    if $test_passed; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠${NC} (may need manual verification)"
    fi
    
    # Test journalctl access
    if command -v journalctl &>/dev/null; then
        echo -n "Testing journalctl access... "
        if sudo -u "$USERNAME" journalctl -n 1 &>/dev/null; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}⚠${NC}"
        fi
    fi
    
    echo ""
    if $all_good; then
        print_success "All checks passed!"
    else
        print_warning "Some checks failed - please review manually"
    fi
}

# Function to start and enable service
start_scalyr_service() {
    print_info "Starting SentinelOne Collector service..."
    
    # Use the official scalyr-agent-2 start command
    # This is the recommended method from SentinelOne documentation
    if command -v scalyr-agent-2 &>/dev/null; then
        scalyr-agent-2 start 2>&1 | tee /tmp/scalyr-start.log
        
        # Check if start was successful
        if grep -q "Configuration and server connection verified" /tmp/scalyr-start.log; then
            print_success "SentinelOne Collector started successfully"
            print_info "Agent is running and watching for configuration changes"
        elif grep -q "starting agent in background" /tmp/scalyr-start.log; then
            print_success "SentinelOne Collector started in background"
        else
            print_warning "Collector may not have started correctly - check logs"
        fi
        
        rm -f /tmp/scalyr-start.log
    else
        # Fallback to systemctl if scalyr-agent-2 command not found
        print_info "Using systemctl as fallback..."
        systemctl daemon-reload
        systemctl enable "$SCALYR_SERVICE" 2>/dev/null || true
        systemctl start "$SCALYR_SERVICE" 2>/dev/null || service "$SCALYR_SERVICE" start
        
        sleep 2
        if systemctl is-active --quiet "$SCALYR_SERVICE" 2>/dev/null; then
            print_success "SentinelOne Collector is running"
        else
            print_warning "Collector may not be running - check: systemctl status $SCALYR_SERVICE"
        fi
    fi
    
    # Check agent status
    sleep 2
    print_info "Checking agent status..."
    if command -v scalyr-agent-2 &>/dev/null; then
        scalyr-agent-2 status || print_warning "Could not verify agent status"
    fi
}

# Main setup function
main() {
    clear
    print_header "SentinelOne Collector Complete Setup & Hardening"
    echo ""
    
    check_root
    detect_os
    confirm_os
    
    echo ""
    print_header "Configuration"
    
    # Ask for username
    read -p "Enter username for Scalyr agent [$USERNAME]: " INPUT_USERNAME
    USERNAME=${INPUT_USERNAME:-$USERNAME}
    
    # Ask for API key FIRST (needed for installation)
    echo ""
    print_info "You need a 'Log Write Access' SDL API key from your SentinelOne Data Lake account"
    read -p "Enter your SentinelOne Data Lake API key: " SCALYR_API_KEY
    while [[ -z "$SCALYR_API_KEY" ]]; do
        print_warning "API key cannot be empty"
        read -p "Enter your SentinelOne Data Lake API key: " SCALYR_API_KEY
    done
    
    # Ask for SentinelOne server URL
    echo ""
    print_info "Enter your SentinelOne Data Lake server URL"
    echo "Examples:"
    echo "  - https://xdr.us1.sentinelone.net"
    echo "  - https://xdr.us2.sentinelone.net"
    echo "  - https://xdr.eu1.sentinelone.net"
    echo "  - https://usea1-020.sentinelone.net"
    read -p "SentinelOne server URL: " SCALYR_SERVER_URL
    while [[ -z "$SCALYR_SERVER_URL" ]]; do
        print_warning "Server URL cannot be empty"
        read -p "SentinelOne server URL: " SCALYR_SERVER_URL
    done
    
    # Validate URL format
    if [[ ! "$SCALYR_SERVER_URL" =~ ^https:// ]]; then
        print_warning "URL should start with https://"
        SCALYR_SERVER_URL="https://$SCALYR_SERVER_URL"
    fi
    
    # Confirmation
    echo ""
    print_header "Configuration Summary"
    echo "Operating System: $OS_TYPE"
    echo "Package Manager: $PACKAGE_MANAGER"
    echo "Username: $USERNAME"
    echo "API Key: ${SCALYR_API_KEY:0:10}..."
    echo "Server URL: $SCALYR_SERVER_URL"
    echo ""
    read -p "Proceed with installation? (y/n): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    fi
    
    echo ""
    print_header "Installation Process"
    
    # Execute installation steps
    install_dependencies
    create_readonly_user
    configure_log_access
    install_scalyr
    configure_scalyr
    harden_scalyr
    start_scalyr_service
    
    echo ""
    verify_installation
    
    echo ""
    print_header "Installation Complete!"
    echo ""
    print_info "Next steps:"
    echo "  1. Verify logs are uploading to SentinelOne Data Lake:"
    echo "     - Visit: $SCALYR_SERVER_URL"
    echo "     - Go to: Policy & Settings > Products > Singularity Data Lake > Custom Log Sources"
    echo "     - Look for your log files in the Overview page"
    echo "  2. Check agent status: scalyr-agent-2 status"
    echo "  3. View agent logs: tail -f /var/log/scalyr-agent-2/agent.log"
    echo "  4. Configuration file: $SCALYR_CONFIG"
    echo "  5. The agent auto-detects config changes within 30 seconds (no restart needed)"
    echo ""
    print_success "SentinelOne Collector is installed, configured, and hardened!"
}

# Run main function
main

exit 0
