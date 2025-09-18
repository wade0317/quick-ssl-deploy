# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Quick SSL Deploy is a shell script tool for one-click deployment of HTTP/HTTPS websites with automatic Nginx configuration and Let's Encrypt SSL certificates. It consists of two main components:
- `quick-ssl-deploy.sh`: Main deployment script with menu-driven interface
- `cert-tool.py`: ACME protocol implementation for SSL certificate generation (based on acme-tiny)

## Development Commands

### Running the Tool
```bash
# Make executable and run with sudo
chmod +x quick-ssl-deploy.sh
sudo ./quick-ssl-deploy.sh

# Or direct execution via curl/wget
curl -sSL https://raw.githubusercontent.com/wade0317/quick-ssl-deploy/master/quick-ssl-deploy.sh | sudo bash
```

### Testing Changes
```bash
# Test script syntax
bash -n quick-ssl-deploy.sh

# Test Python cert tool
python3 cert-tool.py --help
```

## Code Architecture

### Main Script Components (`quick-ssl-deploy.sh`)

The script follows a modular function-based architecture:

1. **System Detection Functions** (`check_*`): Detect OS type, nginx status, SELinux, firewall configurations
2. **Installation Functions** (`install_*`): Handle package installation for different distributions
3. **Configuration Functions**: Generate nginx configs, SSL certificates, set up auto-renewal
4. **Menu System** (`show_main_menu`): Interactive interface for user operations

Key workflows:
- HTTP deployment: `install_http_website()` - Sets up nginx, creates web directory
- HTTPS deployment: `install_https_website()` - HTTP setup + SSL certificate via ACME protocol
- HTTP to HTTPS upgrade: `upgrade_http_to_https()` - Converts existing HTTP sites

### Certificate Tool (`cert-tool.py`)

ACME protocol implementation for Let's Encrypt certificates:
- Handles account key generation
- CSR (Certificate Signing Request) processing
- ACME challenge verification via HTTP-01 method
- Compatible with Python 2/3

## Important Implementation Details

- **Multi-domain Support**: Uses OpenSSL SAN (Subject Alternative Names) for multiple domains on single certificate
- **Auto-renewal**: Sets up cron job at `/etc/cron.monthly/renew_cert` for automatic monthly renewal
- **Cross-platform**: Supports Ubuntu/Debian (apt) and CentOS/RHEL (yum) package managers
- **Cloud Platform Aware**: Detects AWS/Alibaba Cloud/Tencent Cloud environments and provides security group guidance
- **SELinux Handling**: Automatically configures SELinux contexts for web directories on RHEL-based systems

## File Locations

- Default web directory: `/home/{user}/website`
- Nginx configs: `/etc/nginx/sites-available/` (Debian) or `/etc/nginx/conf.d/` (RHEL)
- SSL certificates: `{web_dir}/ssl_cert/`
- Renewal logs: `/var/log/renew_cert.log`