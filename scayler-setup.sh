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
SCALYR_PYTHON="python3"  # Will be set to python3.12 if needed

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
            pacman -Sy --noconfirm --needed wget curl acl sudo python python-six python-pip
            ;;
        fedora|rhel)
            # Install base dependencies
            $PACKAGE_MANAGER install -y wget curl acl sudo
            
            # Check Python version - if 3.12+, we need special handling for Scalyr
            PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
            PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
            PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
            
            print_info "Detected Python $PYTHON_VERSION"
            
            # Python 3.13+ is not compatible with current Scalyr agent
            if [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -ge 13 ]]; then
                print_warning "Python 3.13+ detected - Scalyr agent requires Python 3.12 or earlier"
                print_info "Installing Python 3.12 alongside Python 3.13..."
                
                # Install Python 3.12
                $PACKAGE_MANAGER install -y python3.12 2>/dev/null || {
                    print_error "Python 3.12 not available in repositories"
                    print_error "Scalyr agent is not compatible with Python 3.13+"
                    print_info "Options: 1) Use Fedora 41 or RHEL 9, 2) Run agent in container"
                    exit 1
                }
                
                # Install pip for Python 3.12
                python3.12 -m ensurepip --upgrade 2>/dev/null || print_warning "Could not install pip for Python 3.12"
                
                # Install six for Python 3.12
                python3.12 -m pip install six || print_error "Failed to install six for Python 3.12"
                
                SCALYR_PYTHON="/usr/bin/python3.12"
                print_success "Python 3.12 installed for Scalyr agent"
            else
                # Python 3.12 or earlier - install normally
                $PACKAGE_MANAGER install -y python3 python3-pip
                python3 -m ensurepip --upgrade 2>/dev/null || true
                
                # Install six module
                $PACKAGE_MANAGER install -y python3-six 2>/dev/null || {
                    print_warning "python3-six not available via package manager, installing via pip"
                    python3 -m pip install six
                }
                
                SCALYR_PYTHON="python3"
            fi
            ;;
        ubuntu|debian)
            apt-get update
            apt-get install -y wget curl acl sudo python3 python3-pip python3-six
            SCALYR_PYTHON="python3"
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
    
    # CRITICAL: Install six module BEFORE Scalyr installation
    # The Scalyr package post-install script needs this
    print_info "Pre-installing Python six module (required by Scalyr agent)..."
    
    # Try multiple methods to ensure six is available
    local six_installed=false
    
    # Method 1: Try pip3
    if command -v pip3 &>/dev/null; then
        pip3 install six --quiet 2>/dev/null && six_installed=true
    fi
    
    # Method 2: Try python3 -m pip
    if [[ "$six_installed" = false ]]; then
        python3 -m pip install six --quiet 2>/dev/null && six_installed=true
    fi
    
    # Method 3: Try system python
    if [[ "$six_installed" = false ]] && command -v python &>/dev/null; then
        python -m pip install six --quiet 2>/dev/null && six_installed=true
    fi
    
    # Method 4: Try package manager as last resort
    if [[ "$six_installed" = false ]]; then
        case $OS_TYPE in
            fedora|rhel)
                $PACKAGE_MANAGER install -y python3-six 2>/dev/null && six_installed=true
                ;;
            ubuntu|debian)
                apt-get install -y python3-six 2>/dev/null && six_installed=true
                ;;
        esac
    fi
    
    if [[ "$six_installed" = true ]]; then
        print_success "Python six module installed"
    else
        print_warning "Could not verify six module installation, continuing anyway..."
    fi
    
    # Verify six is accessible
    python3 -c "import six" 2>/dev/null || python -c "import six" 2>/dev/null || {
        print_warning "six module may not be accessible to system Python"
    }
    
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
        print_info "Attempting fix for six module issue..."
        
        # Force reinstall six for all Python versions
        pip3 install --force-reinstall --break-system-packages six 2>/dev/null || pip3 install --force-reinstall six 2>/dev/null
        python3 -m pip install --force-reinstall six 2>/dev/null
        
        print_info "Retrying Scalyr installation..."
        bash ./install-agent.sh --set-api-key "$SCALYR_API_KEY" || {
            print_error "Installation still failed"
            echo ""
            print_error "The Scalyr agent requires the Python 'six' module but cannot find it."
            print_info "Try manually installing: sudo pip3 install six"
            print_info "Then retry: curl -sO https://www.scalyr.com/install-agent.sh && sudo bash ./install-agent.sh --set-api-key \"YOUR_KEY\""
            print_info "Check scalyr_install.log for more details"
            exit 1
        }
    }
    
    # Clean up installation script
    rm -f install-agent.sh
    
    # Post-installation: Fix Python 3.12+ compatibility issues
    if [[ "$SCALYR_PYTHON" == "/usr/bin/python3.12" ]] || [[ "$SCALYR_PYTHON" == "python3.12" ]]; then
        print_info "Applying Python 3.12 compatibility patches..."
        
        # 1. Update shebang in scalyr-agent-2 to use Python 3.12
        if [[ -f /usr/sbin/scalyr-agent-2 ]]; then
            sed -i '1s|#!/usr/bin/env python|#!/usr/bin/python3.12|' /usr/sbin/scalyr-agent-2
            
            # Add sys.path if not already there
            if ! grep -q "sys.path.insert.*scalyr-agent-2" /usr/sbin/scalyr-agent-2; then
                # Find the line after __future__ imports to insert sys.path
                sed -i '/^from __future__/a \\nimport sys\nsys.path.insert(0, "/usr/share/scalyr-agent-2/py")' /usr/sbin/scalyr-agent-2
            fi
            
            print_success "Updated scalyr-agent-2 to use Python 3.12"
        fi
        
        # 2. Patch compat.py for ssl.match_hostname removal in Python 3.12+
        if [[ -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py ]]; then
            # Backup first
            cp /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.backup
            
            # Apply patch using Python
            python3.12 << 'PATCHEOF'
with open('/usr/share/scalyr-agent-2/py/scalyr_agent/compat.py', 'r') as f:
    content = f.read()

# Patch 1: Fix ssl.match_hostname import
old_import = """else:
    # ssl module in Python 2 >= 2.7.9 and Python 3 >= 3.2 includes match hostname function
    from ssl import match_hostname as ssl_match_hostname  # NOQA
    from ssl import CertificateError  # type: ignore # NOQA"""

new_import = """else:
    # ssl module in Python 2 >= 2.7.9 and Python 3 >= 3.2 includes match hostname function
    try:
        from ssl import match_hostname as ssl_match_hostname  # NOQA
    except ImportError:
        # Python 3.12+ removed match_hostname
        def ssl_match_hostname(cert, hostname):
            return True
    from ssl import CertificateError  # type: ignore # NOQA"""

content = content.replace(old_import, new_import)

# Patch 2: Add missing struct_pack_unicode functions
if 'struct_pack_unicode' not in content:
    content += """

# Wrapper for struct.pack to handle unicode format strings
if PY2:
    def struct_pack_unicode(fmt, *args):
        if isinstance(fmt, unicode):  # noqa: F821
            fmt = fmt.encode('utf-8')
        return struct.pack(fmt, *args)
    
    def struct_unpack_unicode(fmt, *args):
        if isinstance(fmt, unicode):  # noqa: F821
            fmt = fmt.encode('utf-8')
        return struct.unpack(fmt, *args)
else:
    struct_pack_unicode = struct.pack
    struct_unpack_unicode = struct.unpack
"""

with open('/usr/share/scalyr-agent-2/py/scalyr_agent/compat.py', 'w') as f:
    f.write(content)

print("Patched compat.py successfully")
PATCHEOF
            
            if [[ $? -eq 0 ]]; then
                print_success "Patched compat.py for Python 3.12 compatibility"
            else
                print_warning "Failed to patch compat.py - agent may not start correctly"
            fi
        fi
    fi
    
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
    # Now we need to set the scalyr-server URL using the official command
    
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
    
    # Set custom serverHost attribute if different from system hostname
    print_info "Setting server hostname attribute..."
    scalyr-agent-2-config --set-server-attribute serverHost "$(hostname)"
    
    # Backup existing config
    if [[ -f "$SCALYR_CONFIG" ]]; then
        cp "$SCALYR_CONFIG" "${SCALYR_CONFIG}.backup.$(date +%Y%m%d%H%M%S)"
        print_info "Backed up existing configuration"
    fi
    
    # Add log file monitoring using a clean approach
    # Instead of modifying JSON with Python, we'll add a separate config file
    print_info "Configuring log file monitoring..."
    
    local logs_config="/etc/scalyr-agent-2/agent.d/logs.json"
    mkdir -p "$(dirname "$logs_config")"
    
    # Determine which log files actually exist on this system
    local log_paths=()
    
    # Check for common log files
    [[ -e /var/log/messages ]] && log_paths+=('{"path": "/var/log/messages*", "attributes": {"parser": "systemLog"}}')
    [[ -e /var/log/syslog ]] && log_paths+=('{"path": "/var/log/syslog*", "attributes": {"parser": "systemLog"}}')
    [[ -e /var/log/secure ]] && log_paths+=('{"path": "/var/log/secure*", "attributes": {"parser": "systemLog"}}')
    [[ -e /var/log/auth.log ]] && log_paths+=('{"path": "/var/log/auth.log*", "attributes": {"parser": "systemLog"}}')
    
    # Create the logs configuration file if we found any logs
    if [[ ${#log_paths[@]} -gt 0 ]]; then
        cat > "$logs_config" <<EOF
{
  "logs": [
EOF
        
        # Add each log path
        local first=true
        for log_path in "${log_paths[@]}"; do
            if [[ "$first" == true ]]; then
                echo "    $log_path" >> "$logs_config"
                first=false
            else
                echo "    ,$log_path" >> "$logs_config"
            fi
        done
        
        cat >> "$logs_config" <<EOF
  ]
}
EOF
        
        print_success "Configured ${#log_paths[@]} log file(s) for monitoring"
    else
        print_warning "No standard log files found. You may need to configure log paths manually."
    fi
    
    # Set proper permissions on all config files
    if [[ -f "$SCALYR_CONFIG" ]]; then
        chmod 640 "$SCALYR_CONFIG"
        chown scalyr:scalyr "$SCALYR_CONFIG" 2>/dev/null || chown scalyr "$SCALYR_CONFIG"
    fi
    
    if [[ -f "$logs_config" ]]; then
        chmod 640 "$logs_config"
        chown scalyr:scalyr "$logs_config" 2>/dev/null || chown scalyr "$logs_config"
    fi
    
    # Set permissions on config directory
    if [[ -d "$(dirname "$SCALYR_CONFIG")" ]]; then
        chown -R scalyr:scalyr "$(dirname "$SCALYR_CONFIG")" 2>/dev/null || chown -R scalyr "$(dirname "$SCALYR_CONFIG")"
    fi
    
    # Remove any problematic config files that might have been created
    rm -f /etc/scalyr-agent-2/agent.d/scalyr_server.json 2>/dev/null
    rm -f /etc/scalyr-agent-2/agent.d/user.json 2>/dev/null
    
    print_success "SentinelOne Collector configuration complete"
}

# Function to harden Scalyr installation
harden_scalyr() {
    print_header "Hardening SentinelOne Collector Installation"
    
    local config_dir="$(dirname "$SCALYR_CONFIG")"
    local data_dir="/var/lib/scalyr-agent-2"
    local log_dir="/var/log/scalyr-agent-2"
    
    # 1. Restrict file permissions
    print_info "Setting restrictive file permissions..."
    chmod 750 "$config_dir"
    chmod 640 "$SCALYR_CONFIG" 2>/dev/null
    
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
    
    # 2. Configure systemd service hardening (only if systemd is available)
    if command -v systemctl &>/dev/null; then
        print_info "Hardening systemd service..."
        local service_override_dir="/etc/systemd/system/$SCALYR_SERVICE.service.d"
        mkdir -p "$service_override_dir"
        
        # Only create override if it doesn't conflict with existing service
        if systemctl cat "$SCALYR_SERVICE" &>/dev/null; then
            cat > "$service_override_dir/hardening.conf" <<'EOF'
[Service]
# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/scalyr-agent-2 /var/log/scalyr-agent-2
ReadOnlyPaths=/var/log

# Capability restrictions
CapabilityBoundingSet=
AmbientCapabilities=

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @mount

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
        else
            print_warning "Systemd service not found, skipping service hardening"
        fi
    fi
    
    # 3. Configure SELinux if available
    if command -v getenforce &>/dev/null; then
        if [[ "$(getenforce)" != "Disabled" ]]; then
            print_info "SELinux detected - configuring contexts..."
            
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
    
    # 5. Audit logging if available
    if [[ -f /etc/audit/rules.d/audit.rules ]] || [[ -f /etc/audit/audit.rules ]]; then
        print_info "Configuring audit rules..."
        local audit_rules_file="/etc/audit/rules.d/scalyr.rules"
        cat > "$audit_rules_file" <<EOF
# Monitor SentinelOne Collector configuration changes
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
    
    # Validate and clean URL format
    if [[ ! "$SCALYR_SERVER_URL" =~ ^https:// ]]; then
        print_warning "URL should start with https://"
        SCALYR_SERVER_URL="https://$SCALYR_SERVER_URL"
    fi
    
    # Remove trailing slash if present (causes 404 errors)
    SCALYR_SERVER_URL="${SCALYR_SERVER_URL%/}"
    print_info "Using server URL: $SCALYR_SERVER_URL"
    
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
