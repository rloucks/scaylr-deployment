#!/bin/bash

#######################################
# SentinelOne Collector Complete Uninstall Script
# Removes: Agent, configs, data, logs, user, systemd overrides
# Supports: Arch, RHEL, Fedora, Ubuntu, Debian
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
PACKAGE_MANAGER=""
USERNAME="scalyr"

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
                OS_TYPE="unknown"
                PACKAGE_MANAGER="unknown"
                ;;
        esac
        
        print_success "Detected: $NAME (${OS_TYPE})"
    else
        print_warning "Cannot detect OS precisely, will attempt generic uninstall"
        OS_TYPE="unknown"
    fi
}

# Function to stop the agent
stop_agent() {
    print_info "Stopping SentinelOne Collector..."
    
    # Try using the agent command first
    if command -v scalyr-agent-2 &>/dev/null; then
        scalyr-agent-2 stop 2>/dev/null || print_warning "Agent was not running or already stopped"
        print_success "Agent stopped"
    fi
    
    # Also try systemctl
    if command -v systemctl &>/dev/null; then
        systemctl stop scalyr-agent-2 2>/dev/null || true
        systemctl disable scalyr-agent-2 2>/dev/null || true
    fi
    
    # Try service command as fallback
    service scalyr-agent-2 stop 2>/dev/null || true
}

# Function to uninstall the package
uninstall_package() {
    print_info "Uninstalling SentinelOne Collector package..."
    
    case $OS_TYPE in
        arch)
            if pacman -Q scalyr-agent-2 &>/dev/null; then
                pacman -R --noconfirm scalyr-agent-2 2>/dev/null || print_warning "Package removal failed or not installed"
            else
                print_info "Package not installed via pacman"
            fi
            ;;
        fedora|rhel)
            if rpm -q scalyr-agent-2 &>/dev/null; then
                $PACKAGE_MANAGER remove -y scalyr-agent-2 2>/dev/null || print_warning "Package removal failed"
            else
                print_info "Package not installed via rpm"
            fi
            ;;
        ubuntu|debian)
            if dpkg -l | grep -q scalyr-agent-2; then
                apt-get remove --purge -y scalyr-agent-2 2>/dev/null || print_warning "Package removal failed"
                apt-get autoremove -y 2>/dev/null || true
            else
                print_info "Package not installed via apt"
            fi
            ;;
        *)
            print_warning "Unknown OS type, skipping package removal"
            ;;
    esac
    
    print_success "Package uninstallation complete"
}

# Function to remove configuration files
remove_configs() {
    print_info "Removing configuration files..."
    
    local removed=0
    
    if [[ -d /etc/scalyr-agent-2 ]]; then
        # Backup before removal
        if [[ -f /etc/scalyr-agent-2/agent.json ]]; then
            local backup_dir="/root/scalyr-backup-$(date +%Y%m%d%H%M%S)"
            mkdir -p "$backup_dir"
            cp -r /etc/scalyr-agent-2 "$backup_dir/" 2>/dev/null || true
            print_info "Backed up configs to: $backup_dir"
        fi
        
        rm -rf /etc/scalyr-agent-2
        removed=1
        print_success "Removed /etc/scalyr-agent-2"
    fi
    
    # Remove any backup files created during installation
    if [[ -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.backup ]]; then
        rm -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.backup
        print_info "Removed compat.py backup"
    fi
    
    if [[ -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.broken ]]; then
        rm -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.broken
        print_info "Removed broken compat.py"
    fi
    
    if [[ $removed -eq 0 ]]; then
        print_info "No configuration files found"
    fi
}

# Function to remove data directory
remove_data() {
    print_info "Removing data directory..."
    
    if [[ -d /var/lib/scalyr-agent-2 ]]; then
        rm -rf /var/lib/scalyr-agent-2
        print_success "Removed /var/lib/scalyr-agent-2"
    else
        print_info "No data directory found"
    fi
}

# Function to remove log directory
remove_logs() {
    print_info "Removing log directory..."
    
    if [[ -d /var/log/scalyr-agent-2 ]]; then
        rm -rf /var/log/scalyr-agent-2
        print_success "Removed /var/log/scalyr-agent-2"
    else
        print_info "No log directory found"
    fi
}

# Function to remove systemd overrides
remove_systemd_overrides() {
    print_info "Removing systemd service overrides..."
    
    local removed=0
    
    if [[ -d /etc/systemd/system/scalyr-agent-2.service.d ]]; then
        rm -rf /etc/systemd/system/scalyr-agent-2.service.d
        removed=1
        print_success "Removed systemd overrides"
    fi
    
    if [[ -f /etc/systemd/system/scalyr-agent-2.service ]]; then
        rm -f /etc/systemd/system/scalyr-agent-2.service
        removed=1
        print_success "Removed systemd service file"
    fi
    
    if [[ $removed -eq 1 ]] && command -v systemctl &>/dev/null; then
        systemctl daemon-reload
        print_success "Reloaded systemd"
    else
        print_info "No systemd overrides found"
    fi
}

# Function to remove user
remove_user() {
    print_info "Removing scalyr user..."
    
    if id "$USERNAME" &>/dev/null; then
        # Kill any processes running as this user
        pkill -u "$USERNAME" 2>/dev/null || true
        
        # Remove the user
        userdel "$USERNAME" 2>/dev/null || userdel -f "$USERNAME" 2>/dev/null || true
        
        # Remove home directory if it exists
        if [[ -d "/home/$USERNAME" ]]; then
            rm -rf "/home/$USERNAME"
        fi
        
        print_success "Removed user: $USERNAME"
    else
        print_info "User $USERNAME does not exist"
    fi
    
    # Remove group if it exists and is empty
    if getent group "$USERNAME" &>/dev/null; then
        groupdel "$USERNAME" 2>/dev/null || true
    fi
}

# Function to remove Python 3.12 patches and backups
remove_patches() {
    print_info "Removing Python compatibility patches and backups..."
    
    local removed=0
    
    # Remove compat.py backup
    if [[ -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.backup ]]; then
        rm -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.backup
        removed=1
    fi
    
    if [[ -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.broken ]]; then
        rm -f /usr/share/scalyr-agent-2/py/scalyr_agent/compat.py.broken
        removed=1
    fi
    
    # Remove any temporary patch files
    rm -f /tmp/patch_compat.py /tmp/fix_compat.py /tmp/clean_patch.py /tmp/compat_fixed.py 2>/dev/null
    
    if [[ $removed -eq 1 ]]; then
        print_success "Removed compatibility patches and backups"
    else
        print_info "No patch files found to remove"
    fi
}

# Function to show Python 3.12 removal note
python312_removal_note() {
    # Check if Python 3.12 was installed separately
    if command -v python3.12 &>/dev/null && command -v python3.13 &>/dev/null; then
        echo ""
        print_warning "Python 3.12 was installed for Scalyr compatibility"
        print_info "If you no longer need Python 3.12, you can remove it:"
        case $OS_TYPE in
            fedora|rhel)
                echo "  sudo dnf remove python3.12"
                ;;
            ubuntu|debian)
                echo "  sudo apt-get remove python3.12"
                ;;
            arch)
                echo "  sudo pacman -R python312"
                ;;
        esac
    fi
}

# Function to remove Python 3.12 if it was installed only for Scalyr
remove_python312() {
    print_info "Checking for Python 3.12 installation..."
    
    # Only offer to remove if Python 3.13+ is the system default
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -ge 13 ]]; then
        if command -v python3.12 &>/dev/null; then
            echo ""
            read -p "Python 3.12 was likely installed for Scalyr. Remove it? (y/n) [n]: " REMOVE_PY312
            if [[ "$REMOVE_PY312" =~ ^[Yy]$ ]]; then
                case $OS_TYPE in
                    fedora|rhel)
                        $PACKAGE_MANAGER remove -y python3.12 2>/dev/null || print_warning "Could not remove python3.12"
                        ;;
                esac
                print_success "Removed Python 3.12"
            else
                print_info "Keeping Python 3.12 installed"
            fi
        fi
    fi
}

# Function to remove repository configuration
remove_repos() {
    print_info "Removing Scalyr repository configuration..."
    
    local removed=0
    
    case $OS_TYPE in
        fedora|rhel)
            if [[ -f /etc/yum.repos.d/scalyr.repo ]]; then
                rm -f /etc/yum.repos.d/scalyr.repo
                removed=1
            fi
            ;;
        ubuntu|debian)
            if [[ -f /etc/apt/sources.list.d/scalyr.list ]]; then
                rm -f /etc/apt/sources.list.d/scalyr.list
                removed=1
            fi
            if [[ -f /usr/share/keyrings/scalyr.gpg ]]; then
                rm -f /usr/share/keyrings/scalyr.gpg
                removed=1
            fi
            if [[ $removed -eq 1 ]]; then
                apt-get update 2>/dev/null || true
            fi
            ;;
    esac
    
    if [[ $removed -eq 1 ]]; then
        print_success "Removed repository configuration"
    else
        print_info "No repository configuration found"
    fi
}

# Function to remove logrotate configuration
remove_logrotate() {
    print_info "Removing logrotate configuration..."
    
    if [[ -f /etc/logrotate.d/scalyr-agent-2 ]]; then
        rm -f /etc/logrotate.d/scalyr-agent-2
        print_success "Removed logrotate configuration"
    else
        print_info "No logrotate configuration found"
    fi
}

# Function to remove audit rules
remove_audit_rules() {
    print_info "Removing audit rules..."
    
    if [[ -f /etc/audit/rules.d/scalyr.rules ]]; then
        rm -f /etc/audit/rules.d/scalyr.rules
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
        print_success "Removed audit rules"
    else
        print_info "No audit rules found"
    fi
}

# Function to remove firewall rules
remove_firewall_rules() {
    print_info "Removing firewall rules..."
    
    # This is tricky as we added specific rules - for safety we'll just notify
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        print_warning "Firewall rules were added - you may want to review: firewall-cmd --list-all"
    fi
    
    print_info "Firewall rules (if any) left in place for safety"
}

# Function to clean up ACLs
cleanup_acls() {
    print_info "Removing ACLs for scalyr user..."
    
    if command -v setfacl &>/dev/null; then
        # Remove ACLs from /var/log
        setfacl -R -x u:$USERNAME /var/log 2>/dev/null || true
        print_success "Removed ACLs"
    else
        print_info "ACL tools not available"
    fi
}

# Function to verify complete removal
verify_removal() {
    print_header "Verifying Complete Removal"
    
    local all_clean=true
    
    # Check for package
    echo -n "Package removed: "
    if command -v scalyr-agent-2 &>/dev/null; then
        echo -e "${RED}✗${NC} (still installed)"
        all_clean=false
    else
        echo -e "${GREEN}✓${NC}"
    fi
    
    # Check for configs
    echo -n "Configs removed: "
    if [[ -d /etc/scalyr-agent-2 ]]; then
        echo -e "${RED}✗${NC} (still present)"
        all_clean=false
    else
        echo -e "${GREEN}✓${NC}"
    fi
    
    # Check for data
    echo -n "Data removed: "
    if [[ -d /var/lib/scalyr-agent-2 ]]; then
        echo -e "${RED}✗${NC} (still present)"
        all_clean=false
    else
        echo -e "${GREEN}✓${NC}"
    fi
    
    # Check for logs
    echo -n "Logs removed: "
    if [[ -d /var/log/scalyr-agent-2 ]]; then
        echo -e "${RED}✗${NC} (still present)"
        all_clean=false
    else
        echo -e "${GREEN}✓${NC}"
    fi
    
    # Check for user
    echo -n "User removed: "
    if id "$USERNAME" &>/dev/null; then
        echo -e "${RED}✗${NC} (still exists)"
        all_clean=false
    else
        echo -e "${GREEN}✓${NC}"
    fi
    
    # Check for systemd
    echo -n "Systemd overrides removed: "
    if [[ -d /etc/systemd/system/scalyr-agent-2.service.d ]]; then
        echo -e "${RED}✗${NC} (still present)"
        all_clean=false
    else
        echo -e "${GREEN}✓${NC}"
    fi
    
    echo ""
    if $all_clean; then
        print_success "Complete removal verified!"
    else
        print_warning "Some items were not fully removed - see above"
    fi
}

# Main uninstall function
main() {
    clear
    print_header "SentinelOne Collector Complete Uninstall"
    echo ""
    
    check_root
    detect_os
    
    echo ""
    print_warning "This will completely remove SentinelOne Collector including:"
    echo "  - Agent package and binaries"
    echo "  - Configuration files"
    echo "  - Data and logs"
    echo "  - Scalyr user account"
    echo "  - Systemd overrides"
    echo "  - Repository configuration"
    echo "  - Logrotate configuration"
    echo "  - Audit rules"
    echo ""
    
    read -p "Are you sure you want to proceed? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        print_info "Uninstall cancelled"
        exit 0
    fi
    
    echo ""
    print_header "Uninstallation Process"
    
    # Execute uninstall steps
    stop_agent
    uninstall_package
    remove_configs
    remove_data
    remove_logs
    remove_systemd_overrides
    remove_logrotate
    remove_audit_rules
    remove_firewall_rules
    remove_repos
    cleanup_acls
    remove_patches
    remove_user
    
    echo ""
    verify_removal
    
    echo ""
    print_header "Uninstallation Complete!"
    echo ""
    print_info "SentinelOne Collector has been removed from your system"
    
    # Check for backups
    if ls /root/scalyr-backup-* &>/dev/null 2>&1; then
        echo ""
        print_info "Configuration backups are available in:"
        ls -d /root/scalyr-backup-* 2>/dev/null || true
        echo ""
        print_warning "These backups contain your API key - delete them if no longer needed"
    fi
    
    # Show Python 3.12 removal note if applicable
    python312_removal_note
    
    echo ""
}

# Run main function
main

exit 0
