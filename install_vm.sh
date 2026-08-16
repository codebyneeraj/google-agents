#!/usr/bin/env bash
# ==============================================================================
# Linux VM Installer & Provisioning Script for Secure SOC Analyst Orchestrator
# Compatible with Ubuntu 20.04+, Debian 11+, and RHEL/Fedora
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}  Secure SOC Analyst Orchestrator - Linux VM Setup   ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Detect Package Manager and Install Dependencies
if command -v apt-get &>/dev/null; then
    echo -e "${BLUE}[*] Detected Debian/Ubuntu system. Updating and installing packages...${NC}"
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-pip python3-venv openssh-server ufw iptables curl git
elif command -v dnf &>/dev/null; then
    echo -e "${BLUE}[*] Detected RHEL/Fedora system. Updating and installing packages...${NC}"
    sudo dnf install -y python3 python3-pip openssh-server iptables curl git
elif command -v yum &>/dev/null; then
    echo -e "${BLUE}[*] Detected CentOS system. Updating and installing packages...${NC}"
    sudo yum install -y python3 python3-pip openssh-server iptables curl git
else
    echo -e "${YELLOW}[!] Warning: Unknown package manager. Please ensure Python 3.10+, ufw/iptables, and OpenSSH are installed.${NC}"
fi

# 2. Configure OpenSSH Server
echo -e "${BLUE}[*] Ensuring OpenSSH server is running and enabled...${NC}"
sudo systemctl enable --now ssh || sudo systemctl enable --now sshd

# 3. Setup Python Virtual Environment
echo -e "${BLUE}[*] Initializing Python Virtual Environment (.venv)...${NC}"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 4. Configure .env if not exists
if [ ! -f .env ]; then
    echo -e "${BLUE}[*] Creating .env from .env.example with live firewall enabled...${NC}"
    cp .env.example .env
    # Enable live firewall automatically for VM deployment
    sed -i 's/ENABLE_LIVE_FIREWALL=false/ENABLE_LIVE_FIREWALL=true/' .env
    echo -e "${GREEN}[+] .env created. Please edit .env to add your GEMINI_API_KEY / ABUSEIPDB_API_KEY.${NC}"
fi

# 5. Grant Sudo Permissions for Firewall Control (Optional / Passwordless)
CURRENT_USER=$(whoami)
SUDOERS_FILE="/etc/sudoers.d/soc_firewall_${CURRENT_USER}"
echo -e "${BLUE}[*] Configuring sudo permissions for UFW / iptables automated response...${NC}"
if sudo -n true 2>/dev/null; then
    echo "${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/ufw, /sbin/iptables, /usr/bin/journalctl" | sudo tee "$SUDOERS_FILE" >/dev/null
    sudo chmod 0440 "$SUDOERS_FILE"
    echo -e "${GREEN}[+] Automated firewall permission configured at ${SUDOERS_FILE}${NC}"
else
    echo -e "${YELLOW}[!] Non-root user: Run 'sudo ./install_vm.sh' or manually configure sudoers if needed.${NC}"
fi

# 6. Summary and Run Instructions
VM_IP=$(hostname -I | awk '{print $1}')

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  Installation Completed Successfully!               ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Your Linux VM IP Address: ${YELLOW}${VM_IP}${NC}"
echo -e "\n${BLUE}To run the live SOC defense system:${NC}"
echo -e "  1. Start the FastAPI Agent Gateway:"
echo -e "     ${YELLOW}source .venv/bin/activate && python main.py --gateway${NC}"
echo -e "     (or: uvicorn src.gateway.server:app --host 0.0.0.0 --port 8080)"
echo -e "\n  2. In a separate terminal, start the real-time Attack Sensor Daemon:"
echo -e "     ${YELLOW}source .venv/bin/activate && sudo python scripts/sensor_daemon.py${NC}"
echo -e "\n  3. From your Windows machine, run the attack test script:"
echo -e "     ${YELLOW}python scripts/attack_simulation.py --target-ip ${VM_IP}${NC}"
echo -e "${GREEN}======================================================${NC}\n"
