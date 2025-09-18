#!/bin/bash

# ========================================
#     Website Easy Install Script v2.0
# ========================================
# 支持 HTTP/HTTPS 网站快速部署
# 自动检测并修复常见系统问题

SCRIPT_VERSION="2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# GitHub仓库Raw地址（方便仓库变更时修改）
GITHUB_RAW_URL="https://raw.githubusercontent.com/wade0317/quick-ssl-deploy/master"

# 下载工具函数
download_file() {
    local url="$1"
    local output="$2"

    # 优先使用curl（更普遍）
    if command -v curl >/dev/null 2>&1; then
        curl -sSL --connect-timeout 10 -o "$output" "$url" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget --no-check-certificate --timeout=10 -q -O "$output" "$url" || return 1
    else
        print_message "$RED" "错误: 系统缺少curl或wget，请先安装其中之一"
        echo "安装方法:"
        echo "  Debian/Ubuntu: apt-get install curl"
        echo "  CentOS/RHEL: yum install curl"
        return 1
    fi
    return 0
}

# ========================================
#            全局变量定义
# ========================================
PUBLIC_IP=""
web_domains=""
web_dir=""
nginx_config_dir="/etc/nginx"
python_command=""
current_user=""
current_user_group=""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ========================================
#            通用函数库
# ========================================

# 打印彩色消息
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 错误退出
exiterr() {
    print_message "$RED" "错误: $1"
    exit 1
}

# 检查IP地址格式
check_ip() {
    local IP_REGEX="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    printf %s "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

# 获取服务器公网IP
get_public_ip() {
    PUBLIC_IP=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short 2>/dev/null)
    if ! check_ip "$PUBLIC_IP"; then
        if command -v curl >/dev/null 2>&1; then
            PUBLIC_IP=$(curl -s --connect-timeout 10 http://ipv4.icanhazip.com 2>/dev/null)
        elif command -v wget >/dev/null 2>&1; then
            PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com 2>/dev/null)
        fi
    fi
    check_ip "$PUBLIC_IP" || exiterr "无法获取服务器IP地址"
}

# 获取当前用户信息
get_current_user() {
    # 尝试多种方式获取实际用户
    current_user=$(who am i 2>/dev/null | awk '{print $1}')
    if [ -z "$current_user" ]; then
        current_user=$SUDO_USER
    fi
    if [ -z "$current_user" ]; then
        current_user=$USER
    fi
    if [ -z "$current_user" ]; then
        current_user=$(whoami)
    fi
    # 获取用户组
    if id -gn $current_user >/dev/null 2>&1; then
        current_user_group=$(id -gn $current_user)
    else
        current_user_group=$current_user
    fi
}

# 检测操作系统类型
detect_os() {
    if [ -f /etc/redhat-release ]; then
        OS_TYPE="rhel"
        OS_VERSION=$(rpm -E %{rhel})
    elif [ -f /etc/debian_version ]; then
        OS_TYPE="debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        OS_TYPE="unknown"
        OS_VERSION="unknown"
    fi
}

# ========================================
#            系统检测函数库
# ========================================

# 检测Nginx安装状态
check_nginx() {
    if command -v nginx > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 检测EPEL仓库（仅CentOS/RHEL）
check_epel() {
    if [ "$OS_TYPE" = "rhel" ]; then
        if rpm -qa | grep -q epel-release; then
            return 0
        else
            return 1
        fi
    fi
    return 0  # 非RHEL系统默认返回成功
}

# 检测SELinux状态
check_selinux() {
    if command -v getenforce > /dev/null 2>&1; then
        local status=$(getenforce)
        if [ "$status" = "Enforcing" ]; then
            return 1  # SELinux启用，可能有问题
        elif [ "$status" = "Permissive" ]; then
            return 2  # SELinux宽容模式
        fi
    fi
    return 0  # SELinux禁用或不存在
}

# 检测防火墙状态
check_firewall() {
    local firewall_type=""
    local ports_open=true

    # 检测firewalld
    if systemctl is-active firewalld > /dev/null 2>&1; then
        firewall_type="firewalld"
        # 检查端口是否开放
        if ! firewall-cmd --list-services 2>/dev/null | grep -q "http"; then
            ports_open=false
        fi
    # 检测ufw
    elif command -v ufw > /dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        firewall_type="ufw"
        if ! ufw status | grep -qE "80/tcp|443/tcp"; then
            ports_open=false
        fi
    # 检测iptables
    elif command -v iptables > /dev/null 2>&1; then
        firewall_type="iptables"
        if ! iptables -L INPUT -n | grep -qE "dpt:80|dpt:443"; then
            ports_open=false
        fi
    fi

    if [ -n "$firewall_type" ] && [ "$ports_open" = false ]; then
        return 1
    fi
    return 0
}

# 检测云平台
detect_cloud_platform() {
    local platform=""

    # AWS EC2
    if [ -f /sys/hypervisor/uuid ] && grep -q "^ec2" /sys/hypervisor/uuid 2>/dev/null; then
        platform="AWS EC2"
    # 阿里云
    elif curl -s --connect-timeout 1 http://100.100.100.200 > /dev/null 2>&1; then
        platform="阿里云"
    # Google Cloud
    elif curl -s --connect-timeout 1 "http://metadata.google.internal" > /dev/null 2>&1; then
        platform="Google Cloud"
    # 腾讯云
    elif curl -s --connect-timeout 1 "http://metadata.tencentyun.com" > /dev/null 2>&1; then
        platform="腾讯云"
    fi

    if [ -n "$platform" ]; then
        echo "$platform"
        return 0
    fi
    return 1
}

# ========================================
#            修复函数库
# ========================================

# 安装Nginx
install_nginx() {
    print_message "$YELLOW" "开始安装Nginx..."

    if [ "$OS_TYPE" = "rhel" ]; then
        # 检查并安装EPEL
        if ! check_epel; then
            print_message "$YELLOW" "安装EPEL仓库..."
            yum install -y epel-release || \
            yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_VERSION}.noarch.rpm
        fi
        yum install -y nginx
    elif [ "$OS_TYPE" = "debian" ]; then
        apt-get update
        apt-get install -y nginx
    else
        print_message "$RED" "不支持的操作系统"
        return 1
    fi

    # 启动Nginx
    systemctl enable nginx
    systemctl start nginx

    print_message "$GREEN" "Nginx安装完成"
    return 0
}

# 修复SELinux问题
fix_selinux() {
    print_message "$YELLOW" "\nSELinux修复选项："
    echo "1) 为Nginx配置正确的SELinux上下文（推荐）"
    echo "2) 临时设置为Permissive模式"
    echo "3) 永久禁用SELinux（需要重启）"
    echo "4) 跳过"

    read -p "请选择 [1-4]: " choice

    case $choice in
        1)
            print_message "$YELLOW" "配置SELinux上下文..."
            # 安装必要工具
            yum install -y policycoreutils-python-utils 2>/dev/null || \
            yum install -y policycoreutils-python 2>/dev/null

            # 设置上下文
            semanage fcontext -a -t httpd_sys_content_t "/usr/share/nginx/html(/.*)?" 2>/dev/null
            restorecon -Rv /usr/share/nginx/html 2>/dev/null
            setsebool -P httpd_can_network_connect 1 2>/dev/null

            print_message "$GREEN" "SELinux上下文配置完成"
            ;;
        2)
            setenforce 0
            print_message "$GREEN" "SELinux已设置为Permissive模式（临时）"
            ;;
        3)
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
            print_message "$YELLOW" "SELinux已禁用，需要重启系统生效"
            ;;
        4)
            print_message "$YELLOW" "跳过SELinux配置"
            ;;
        *)
            print_message "$RED" "无效选择"
            ;;
    esac
}

# 配置防火墙
configure_firewall() {
    print_message "$YELLOW" "\n配置防火墙规则..."

    # firewalld
    if systemctl is-active firewalld > /dev/null 2>&1; then
        print_message "$YELLOW" "检测到firewalld，添加规则..."
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
        print_message "$GREEN" "firewalld规则已添加"

    # ufw
    elif command -v ufw > /dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        print_message "$YELLOW" "检测到ufw，添加规则..."
        ufw allow 80/tcp
        ufw allow 443/tcp
        print_message "$GREEN" "ufw规则已添加"

    # iptables
    elif command -v iptables > /dev/null 2>&1; then
        print_message "$YELLOW" "检测到iptables，添加规则..."
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT

        # 保存规则
        if [ "$OS_TYPE" = "rhel" ]; then
            service iptables save 2>/dev/null
        elif [ "$OS_TYPE" = "debian" ]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        print_message "$GREEN" "iptables规则已添加"
    else
        print_message "$YELLOW" "未检测到活动的防火墙"
    fi
}

# ========================================
#            系统检测主函数
# ========================================

# 执行完整系统检测
run_full_detection() {
    echo ""
    print_message "$GREEN" "========================================"
    print_message "$GREEN" "           系统检测报告"
    print_message "$GREEN" "========================================"

    detect_os
    echo ""

    # 操作系统信息
    if [ "$OS_TYPE" != "unknown" ]; then
        print_message "$GREEN" "[✓] 操作系统: $OS_TYPE $OS_VERSION"
    else
        print_message "$YELLOW" "[!] 操作系统: 未知"
    fi

    # 网络连接
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        print_message "$GREEN" "[✓] 网络连接: 正常"
    else
        print_message "$RED" "[✗] 网络连接: 异常"
    fi

    # Nginx状态
    if check_nginx; then
        print_message "$GREEN" "[✓] Nginx: 已安装"
    else
        print_message "$RED" "[✗] Nginx: 未安装"
    fi

    # SELinux状态
    selinux_status=$(check_selinux; echo $?)
    if [ $selinux_status -eq 0 ]; then
        print_message "$GREEN" "[✓] SELinux: 已禁用或不存在"
    elif [ $selinux_status -eq 1 ]; then
        print_message "$YELLOW" "[!] SELinux: Enforcing模式（可能影响Nginx）"
    else
        print_message "$YELLOW" "[!] SELinux: Permissive模式"
    fi

    # 防火墙状态
    if check_firewall; then
        print_message "$GREEN" "[✓] 防火墙: 已配置或未启用"
    else
        print_message "$YELLOW" "[!] 防火墙: 需要配置80/443端口"
    fi

    # 云平台检测
    if cloud=$(detect_cloud_platform); then
        print_message "$YELLOW" "[!] 云平台: $cloud（请确保安全组已开放80/443端口）"
    fi

    echo ""
    print_message "$GREEN" "========================================"
    echo ""

    # 提供修复建议
    local need_fix=false

    if ! check_nginx; then
        print_message "$YELLOW" "建议: 安装Nginx"
        need_fix=true
    fi

    if [ $(check_selinux; echo $?) -eq 1 ]; then
        print_message "$YELLOW" "建议: 配置SELinux或设置为Permissive模式"
        need_fix=true
    fi

    if ! check_firewall; then
        print_message "$YELLOW" "建议: 配置防火墙开放80/443端口"
        need_fix=true
    fi

    if [ "$need_fix" = true ]; then
        echo ""
        read -p "是否自动修复所有问题？[Y/n]: " fix_all
        if [[ "$fix_all" =~ ^[Yy]$ ]] || [ -z "$fix_all" ]; then
            fix_all_issues
        fi
    else
        print_message "$GREEN" "系统状态良好，无需修复！"
    fi
}

# 修复所有问题
fix_all_issues() {
    if ! check_nginx; then
        install_nginx
    fi

    if [ $(check_selinux; echo $?) -eq 1 ]; then
        fix_selinux
    fi

    if ! check_firewall; then
        configure_firewall
    fi

    print_message "$GREEN" "\n所有问题修复完成！"
}

# 系统检测菜单
show_detection_menu() {
    while true; do
        echo ""
        print_message "$GREEN" "========================================"
        print_message "$GREEN" "        系统检测与问题修复"
        print_message "$GREEN" "========================================"
        echo ""
        echo "1) 执行完整系统检测"
        echo "2) 检测并修复Nginx安装问题"
        echo "3) 检测并修复SELinux问题"
        echo "4) 检测并配置防火墙"
        echo "5) 返回主菜单"
        echo ""

        read -p "请选择 [1-5]: " choice

        case $choice in
            1)
                run_full_detection
                ;;
            2)
                if check_nginx; then
                    print_message "$GREEN" "Nginx已安装"
                else
                    print_message "$YELLOW" "Nginx未安装"
                    read -p "是否安装Nginx？[Y/n]: " install_choice
                    if [[ "$install_choice" =~ ^[Yy]$ ]] || [ -z "$install_choice" ]; then
                        install_nginx
                    fi
                fi
                ;;
            3)
                selinux_status=$(check_selinux; echo $?)
                if [ $selinux_status -eq 0 ]; then
                    print_message "$GREEN" "SELinux已禁用或不存在"
                elif [ $selinux_status -eq 1 ]; then
                    print_message "$YELLOW" "SELinux处于Enforcing模式"
                    fix_selinux
                else
                    print_message "$YELLOW" "SELinux处于Permissive模式"
                fi
                ;;
            4)
                if check_firewall; then
                    print_message "$GREEN" "防火墙已配置或未启用"
                else
                    print_message "$YELLOW" "防火墙需要配置"
                    read -p "是否配置防火墙规则？[Y/n]: " fw_choice
                    if [[ "$fw_choice" =~ ^[Yy]$ ]] || [ -z "$fw_choice" ]; then
                        configure_firewall
                    fi
                fi
                ;;
            5)
                break
                ;;
            *)
                print_message "$RED" "无效选择，请重试"
                ;;
        esac
    done
}

# ========================================
#            HTTP网站安装函数
# ========================================

setup_http_website() {
    print_message "$GREEN" "\n开始配置HTTP网站..."

    get_public_ip
    echo "服务器IP: ${PUBLIC_IP}"
    echo ""
    echo "请输入网站域名（已解析到 $PUBLIC_IP）"
    echo "多个域名用空格分隔，留空则接受任意域名访问"
    read -p "> " web_domains

    # 处理域名
    web_first_domain=$(echo $web_domains | tr -s [:blank:] | cut -d ' ' -f 1)
    nginx_web_config_file=$web_first_domain".conf"
    nginx_web_config_domain=$web_domains
    web_names=$web_domains

    if [[ -z $(echo $web_domains | sed 's/ //g') ]]; then
        nginx_web_config_domain='~^.*$'
        web_names="任意域名"
        nginx_web_config_file="free_domain_web.conf"
    fi

    # 输入Web程序目录
    echo ""
    echo "请输入Web程序目录的绝对路径"
    echo "如果输入相对路径，将以当前目录为基准"
    read -p "> " web_dir

    if [[ ! "$web_dir" == /* ]]; then
        web_dir=$(pwd)"/"$web_dir
    fi

    # 输入Nginx配置目录
    echo ""
    echo "请输入Nginx配置目录（默认: /etc/nginx）"
    read -p "> " nginx_config_dir

    if [[ -z "$nginx_config_dir" ]]; then
        nginx_config_dir=/etc/nginx
    fi

    # 确认信息
    echo ""
    print_message "$GREEN" "配置信息如下："
    echo "Web程序目录: $web_dir"
    echo "网站域名: $web_names"
    echo "Nginx配置目录: $nginx_config_dir"
    echo ""
    echo "1) 确认"
    echo "2) 取消"
    read -p "> " confirm

    if [[ $confirm -eq 2 ]]; then
        return
    fi

    # 创建目录
    mkdir -p ${web_dir}

    # 设置目录权限
    cur_chmod_dir=$web_dir
    while [[ $cur_chmod_dir != / ]]; do
        chmod o+x "$cur_chmod_dir"
        cur_chmod_dir=$(dirname "$cur_chmod_dir")
    done

    # 创建Nginx配置
    cat > $nginx_config_dir"/conf.d/"$nginx_web_config_file <<EOF
server {
    listen 80;
    server_name $nginx_web_config_domain;
    root $web_dir;
    index index.html index.htm index.php;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # 创建默认首页
    if [[ ! -f $web_dir/index.html ]]; then
        cat > $web_dir/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>HTTP网站创建成功</h1>
    <p>域名: $web_names</p>
    <p>目录: $web_dir</p>
</body>
</html>
EOF
    fi

    # 设置文件权限
    get_current_user
    chown -R $current_user:$current_user_group $web_dir
    chown $current_user:$current_user_group $nginx_config_dir"/conf.d/"$nginx_web_config_file
    chmod -R 755 $web_dir

    # 重启Nginx
    service nginx restart || systemctl restart nginx

    print_message "$GREEN" "\nHTTP网站配置完成！"
    echo "Web程序目录: $web_dir"
    echo "Nginx配置: $nginx_config_dir/conf.d/$nginx_web_config_file"
    echo "访问地址: http://$web_names"
}

# ========================================
#            HTTPS网站安装函数
# ========================================

# 检查Python环境
check_python() {
    if command -v python > /dev/null 2>&1; then
        python_command=python
    elif command -v python3 > /dev/null 2>&1; then
        python_command=python3
    else
        print_message "$YELLOW" "未检测到Python环境，正在安装..."
        if [ "$OS_TYPE" = "rhel" ]; then
            yum -y install python3 || yum -y install python
        else
            apt-get -y install python3 || apt-get -y install python
        fi

        if command -v python3 > /dev/null 2>&1; then
            python_command=python3
        elif command -v python > /dev/null 2>&1; then
            python_command=python
        else
            exiterr "Python安装失败"
        fi
    fi

    print_message "$GREEN" "Python环境检查通过: $python_command"
}

# 检查OpenSSL
check_openssl() {
    if ! command -v openssl > /dev/null 2>&1; then
        print_message "$YELLOW" "未检测到OpenSSL，正在安装..."
        if [ "$OS_TYPE" = "rhel" ]; then
            yum -y install openssl
        else
            apt-get -y install openssl
        fi
    fi

    print_message "$GREEN" "OpenSSL检查通过"
}

setup_https_website() {
    print_message "$GREEN" "\n开始配置HTTPS网站..."

    # 检查依赖
    check_python
    check_openssl

    get_public_ip
    echo "服务器IP: ${PUBLIC_IP}"
    echo ""
    echo "请输入网站域名（已解析到 $PUBLIC_IP）"
    echo "多个域名用空格分隔"
    read -p "> " web_domains

    if [[ -z "$web_domains" ]]; then
        print_message "$RED" "HTTPS网站必须指定域名"
        return
    fi

    # 处理域名
    domain_length=0
    sign_domain_str=''
    web_first_domain=$(echo $web_domains | tr -s [:blank:] | cut -d ' ' -f 1)
    nginx_web_config_file=$web_first_domain".conf"

    for web_domain in ${web_domains[@]}; do
        sign_domain_str=$sign_domain_str"DNS:"$web_domain","
        domain_length=$(($domain_length+1))
    done
    sign_domain_str=${sign_domain_str:0:${#sign_domain_str}-1}

    # 输入Web程序目录
    echo ""
    echo "请输入Web程序目录的绝对路径"
    echo "如果输入相对路径，将以当前目录为基准"
    read -p "> " web_dir

    if [[ ! "$web_dir" == /* ]]; then
        web_dir=$(pwd)"/"$web_dir
    fi

    # 输入证书存放目录
    echo ""
    echo "请输入SSL证书存放目录的绝对路径"
    echo "默认: /etc/letsencrypt/certificates/$web_first_domain"
    read -p "> " cert_dir

    if [[ -z "$cert_dir" ]]; then
        cert_dir="/etc/letsencrypt/certificates/$web_first_domain"
    elif [[ ! "$cert_dir" == /* ]]; then
        cert_dir=$(pwd)"/"$cert_dir
    fi

    # 输入Nginx配置目录
    echo ""
    echo "请输入Nginx配置目录（默认: /etc/nginx）"
    read -p "> " nginx_config_dir

    if [[ -z "$nginx_config_dir" ]]; then
        nginx_config_dir=/etc/nginx
    fi

    # 确认信息
    echo ""
    print_message "$GREEN" "配置信息如下："
    echo "Web程序目录: $web_dir"
    echo "SSL证书目录: $cert_dir"
    echo "网站域名: $web_domains"
    echo "Nginx配置目录: $nginx_config_dir"
    echo ""
    echo "1) 确认"
    echo "2) 取消"
    read -p "> " confirm

    if [[ $confirm -eq 2 ]]; then
        return
    fi

    # 创建目录
    mkdir -p ${web_dir}
    mkdir -p ${cert_dir}"/challenges"

    # 设置目录权限
    cur_chmod_dir=$web_dir
    while [[ $cur_chmod_dir != / ]]; do
        chmod o+x "$cur_chmod_dir"
        cur_chmod_dir=$(dirname "$cur_chmod_dir")
    done

    cur_chmod_dir=$cert_dir
    while [[ $cur_chmod_dir != / ]]; do
        chmod o+x "$cur_chmod_dir"
        cur_chmod_dir=$(dirname "$cur_chmod_dir")
    done

    cd $cert_dir

    # 创建账户密钥
    print_message "$YELLOW" "生成账户密钥..."
    openssl genrsa 4096 > account.key

    # 创建域名密钥
    print_message "$YELLOW" "生成域名密钥..."
    openssl genrsa 4096 > domain.key

    # 创建证书签名请求
    print_message "$YELLOW" "生成证书签名请求..."
    if [[ $domain_length -gt 1 ]]; then
        openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=$sign_domain_str")) > domain.csr || \
        openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/pki/tls/openssl.cnf <(printf "[SAN]\nsubjectAltName=$sign_domain_str")) > domain.csr
    else
        openssl req -new -sha256 -key domain.key -subj "/CN=$web_domains" > domain.csr
    fi

    # 创建临时HTTP配置用于验证
    cat > $nginx_config_dir"/conf.d/"$nginx_web_config_file <<EOF
server {
    listen 80;
    server_name $web_domains;
    location /.well-known/acme-challenge/ {
        alias $cert_dir/challenges/;
        try_files \$uri =404;
    }
}
EOF

    service nginx restart || systemctl restart nginx

    # 使用acme_tiny获取证书
    print_message "$YELLOW" "申请SSL证书..."

    # 检查本地证书工具
    if [[ -f "$SCRIPT_DIR/cert-tool.py" ]]; then
        cp "$SCRIPT_DIR/cert-tool.py" ./cert-tool.py
    else
        download_file "${GITHUB_RAW_URL}/cert-tool.py" cert-tool.py || exiterr "无法下载证书工具"
    fi

    $python_command cert-tool.py --account-key ./account.key --csr ./domain.csr --acme-dir $cert_dir/challenges > ./signed.crt || exiterr "证书申请失败，请检查域名解析是否正确"

    # 下载中间证书
    print_message "$YELLOW" "下载中间证书..."
    download_file https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem intermediate.pem || exiterr "无法下载中间证书"
    cat signed.crt intermediate.pem > chained.pem

    # 创建HTTPS配置
    cat > $nginx_config_dir"/conf.d/"$nginx_web_config_file <<EOF
server {
    listen 80;
    server_name $web_domains;
    rewrite ^(.*) https://\$host\$1 permanent;
}

server {
    listen 443 ssl;
    server_name $web_domains;
    root $web_dir;
    index index.html index.htm index.php;

    ssl_certificate $cert_dir/chained.pem;
    ssl_certificate_key $cert_dir/domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:50m;
    ssl_prefer_server_ciphers on;

    location /.well-known/acme-challenge/ {
        alias $cert_dir/challenges/;
        try_files \$uri =404;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # 创建默认首页
    if [[ ! -f $web_dir/index.html ]]; then
        cat > $web_dir/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>HTTPS网站创建成功</h1>
    <p>域名: $web_domains</p>
    <p>目录: $web_dir</p>
    <p>SSL证书: Let's Encrypt</p>
</body>
</html>
EOF
    fi

    # 创建证书续期脚本
    cat > $cert_dir/renew_cert.bash <<EOF
#!/bin/bash
cd $cert_dir

# 下载工具函数
download_file() {
    local url="\$1"
    local output="\$2"
    if command -v curl >/dev/null 2>&1; then
        curl -sSL --connect-timeout 10 -o "\$output" "\$url" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget --no-check-certificate --timeout=10 -q -O "\$output" "\$url" || return 1
    else
        echo "错误: 系统缺少curl或wget"
        return 1
    fi
    return 0
}

# 使用本地证书工具，如果不存在则下载
script_dir="$SCRIPT_DIR"
if [[ -f "\$script_dir/cert-tool.py" ]]; then
    cp "\$script_dir/cert-tool.py" ./cert-tool.py
else
    download_file "${GITHUB_RAW_URL}/cert-tool.py" cert-tool.py || exit 1
fi

$python_command ./cert-tool.py --account-key ./account.key --csr ./domain.csr --acme-dir $cert_dir/challenges/ > /tmp/signed.crt || exit
download_file "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem" intermediate.pem || exit 1
cat /tmp/signed.crt intermediate.pem > $cert_dir/chained.pem
service nginx reload || systemctl reload nginx
EOF

    chmod +x $cert_dir/renew_cert.bash

    # 设置文件权限
    get_current_user
    chown -R $current_user:$current_user_group $web_dir
    chown -R $current_user:$current_user_group $cert_dir
    chown $current_user:$current_user_group $nginx_config_dir"/conf.d/"$nginx_web_config_file
    chmod -R 755 $web_dir
    chmod -R 700 $cert_dir

    # 设置定时任务
    if command -v crontab > /dev/null 2>&1; then
        print_message "$YELLOW" "设置证书自动续期任务..."
        random_day=$((RANDOM % 28 + 1))
        echo "1 1 $random_day * * root bash $cert_dir/renew_cert.bash >> /var/log/renew_cert.log 2>&1" >> /etc/crontab
        print_message "$GREEN" "证书续期任务已创建（每月$random_day日凌晨1点1分执行）"
    fi

    # 重启Nginx
    service nginx restart || systemctl restart nginx

    print_message "$GREEN" "\nHTTPS网站配置完成！"
    echo "Web程序目录: $web_dir"
    echo "SSL证书目录: $cert_dir"
    echo "Nginx配置: $nginx_config_dir/conf.d/$nginx_web_config_file"
    echo ""

    for web_domain in ${web_domains[@]}; do
        echo "访问地址: https://$web_domain"
    done
}

# ========================================
#            HTTP升级HTTPS函数
# ========================================

upgrade_http_to_https() {
    print_message "$GREEN" "\n开始HTTP升级到HTTPS..."

    # 检查依赖
    check_python
    check_openssl

    # 列出现有的HTTP站点配置
    echo ""
    echo "检测现有HTTP站点配置..."

    if [ ! -d "$nginx_config_dir/conf.d" ]; then
        print_message "$RED" "未找到Nginx配置目录"
        return
    fi

    # 查找只有HTTP没有HTTPS的配置文件
    http_configs=""
    for conf in $nginx_config_dir/conf.d/*.conf; do
        if [[ -f "$conf" ]]; then
            if grep -q "listen 80" "$conf" && ! grep -q "listen 443" "$conf"; then
                http_configs="$http_configs $conf"
            fi
        fi
    done
    http_configs=$(echo $http_configs | xargs)

    if [ -z "$http_configs" ]; then
        print_message "$RED" "未找到HTTP站点配置"
        return
    fi

    echo "找到以下HTTP配置文件："
    select config_file in $http_configs "返回"; do
        if [ "$config_file" = "返回" ]; then
            return
        elif [ -n "$config_file" ]; then
            break
        fi
    done

    # 解析配置文件获取域名和目录
    web_domains=$(grep "server_name" $config_file | head -1 | sed 's/.*server_name//' | sed 's/;//' | xargs)
    web_dir=$(grep "root" $config_file | head -1 | sed 's/.*root//' | sed 's/;//' | xargs)

    if [ -z "$web_domains" ] || [ -z "$web_dir" ]; then
        print_message "$RED" "无法解析配置文件"
        return
    fi

    print_message "$GREEN" "将升级以下站点："
    echo "域名: $web_domains"
    echo "Web程序目录: $web_dir"

    # 获取第一个域名用于默认证书目录
    web_first_domain=$(echo $web_domains | tr -s [:blank:] | cut -d ' ' -f 1)

    # 输入证书存放目录
    echo ""
    echo "请输入SSL证书存放目录的绝对路径"
    echo "默认: /etc/letsencrypt/certificates/$web_first_domain"
    read -p "> " cert_dir

    if [[ -z "$cert_dir" ]]; then
        cert_dir="/etc/letsencrypt/certificates/$web_first_domain"
    elif [[ ! "$cert_dir" == /* ]]; then
        cert_dir=$(pwd)"/"$cert_dir
    fi

    echo ""
    echo "SSL证书目录: $cert_dir"
    echo ""

    read -p "确认升级？[Y/n]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]] && [ -n "$confirm" ]; then
        return
    fi

    # 备份原配置
    cp $config_file ${config_file}.bak.$(date +%Y%m%d%H%M%S)

    # 创建证书目录
    mkdir -p ${cert_dir}"/challenges"

    # 设置目录权限
    cur_chmod_dir=$web_dir
    while [[ $cur_chmod_dir != / ]]; do
        chmod o+x "$cur_chmod_dir"
        cur_chmod_dir=$(dirname "$cur_chmod_dir")
    done

    cur_chmod_dir=$cert_dir
    while [[ $cur_chmod_dir != / ]]; do
        chmod o+x "$cur_chmod_dir"
        cur_chmod_dir=$(dirname "$cur_chmod_dir")
    done

    cd $cert_dir

    # 处理域名
    domain_length=0
    sign_domain_str=''

    for web_domain in ${web_domains[@]}; do
        sign_domain_str=$sign_domain_str"DNS:"$web_domain","
        domain_length=$(($domain_length+1))
    done
    sign_domain_str=${sign_domain_str:0:${#sign_domain_str}-1}

    # 创建证书
    print_message "$YELLOW" "生成SSL证书..."
    openssl genrsa 4096 > account.key
    openssl genrsa 4096 > domain.key

    if [[ $domain_length -gt 1 ]]; then
        openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=$sign_domain_str")) > domain.csr || \
        openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/pki/tls/openssl.cnf <(printf "[SAN]\nsubjectAltName=$sign_domain_str")) > domain.csr
    else
        openssl req -new -sha256 -key domain.key -subj "/CN=$web_domains" > domain.csr
    fi

    # 添加ACME验证位置到现有配置
    sed -i '/server {/a \    location /.well-known/acme-challenge/ {\n        alias '"$cert_dir"'/challenges/;\n        try_files $uri =404;\n    }' $config_file

    service nginx restart || systemctl restart nginx

    # 申请证书
    if [[ -f "$SCRIPT_DIR/cert-tool.py" ]]; then
        cp "$SCRIPT_DIR/cert-tool.py" ./cert-tool.py
    else
        download_file "${GITHUB_RAW_URL}/cert-tool.py" cert-tool.py || exiterr "无法下载证书工具"
    fi

    $python_command cert-tool.py --account-key ./account.key --csr ./domain.csr --acme-dir $cert_dir/challenges > ./signed.crt || exiterr "证书申请失败"

    download_file "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem" intermediate.pem || exiterr "无法下载中间证书"
    cat signed.crt intermediate.pem > chained.pem

    # 更新Nginx配置为HTTPS
    cat > $config_file <<EOF
server {
    listen 80;
    server_name $web_domains;
    rewrite ^(.*) https://\$host\$1 permanent;
}

server {
    listen 443 ssl;
    server_name $web_domains;
    root $web_dir;
    index index.html index.htm index.php;

    ssl_certificate $cert_dir/chained.pem;
    ssl_certificate_key $cert_dir/domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:50m;
    ssl_prefer_server_ciphers on;

    location /.well-known/acme-challenge/ {
        alias $cert_dir/challenges/;
        try_files \$uri =404;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # 创建证书续期脚本
    cat > $cert_dir/renew_cert.bash <<EOF
#!/bin/bash
cd $cert_dir

# 下载工具函数
download_file() {
    local url="\$1"
    local output="\$2"
    if command -v curl >/dev/null 2>&1; then
        curl -sSL --connect-timeout 10 -o "\$output" "\$url" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget --no-check-certificate --timeout=10 -q -O "\$output" "\$url" || return 1
    else
        echo "错误: 系统缺少curl或wget"
        return 1
    fi
    return 0
}

script_dir="$SCRIPT_DIR"
if [[ -f "\$script_dir/cert-tool.py" ]]; then
    cp "\$script_dir/cert-tool.py" ./cert-tool.py
else
    download_file "${GITHUB_RAW_URL}/cert-tool.py" cert-tool.py || exit 1
fi

$python_command ./cert-tool.py --account-key ./account.key --csr ./domain.csr --acme-dir $cert_dir/challenges/ > /tmp/signed.crt || exit
download_file "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem" intermediate.pem || exit 1
cat /tmp/signed.crt intermediate.pem > $cert_dir/chained.pem
service nginx reload || systemctl reload nginx
EOF

    chmod +x $cert_dir/renew_cert.bash

    # 设置权限
    get_current_user
    chown -R $current_user:$current_user_group $cert_dir
    chmod -R 700 $cert_dir

    # 设置定时任务
    if command -v crontab > /dev/null 2>&1; then
        random_day=$((RANDOM % 28 + 1))
        echo "1 1 $random_day * * root bash $cert_dir/renew_cert.bash >> /var/log/renew_cert.log 2>&1" >> /etc/crontab
    fi

    # 重启Nginx
    service nginx restart || systemctl restart nginx

    print_message "$GREEN" "\nHTTP站点已成功升级为HTTPS！"
    echo "备份文件: ${config_file}.bak.*"
    echo ""

    for web_domain in ${web_domains[@]}; do
        echo "访问地址: https://$web_domain"
    done
}

# ========================================
#            主菜单系统
# ========================================

show_main_menu() {
    while true; do
        echo ""
        print_message "$GREEN" "========================================"
        print_message "$GREEN" "    Website Easy Install v$SCRIPT_VERSION"
        print_message "$GREEN" "========================================"
        echo ""
        echo "1) 安装HTTP网站"
        echo "2) 安装HTTPS网站（自动SSL）"
        echo "3) 将现有HTTP升级为HTTPS"
        echo "4) 系统检测与问题修复"
        echo "5) 退出"
        echo ""

        read -p "请选择 [1-5]: " choice

        case $choice in
            1)
                detect_os
                if ! check_nginx; then
                    print_message "$YELLOW" "Nginx未安装，需要先安装Nginx"
                    read -p "是否安装？[Y/n]: " install_choice
                    if [[ "$install_choice" =~ ^[Yy]$ ]] || [ -z "$install_choice" ]; then
                        install_nginx
                    else
                        continue
                    fi
                fi
                setup_http_website
                ;;
            2)
                detect_os
                if ! check_nginx; then
                    print_message "$YELLOW" "Nginx未安装，需要先安装Nginx"
                    read -p "是否安装？[Y/n]: " install_choice
                    if [[ "$install_choice" =~ ^[Yy]$ ]] || [ -z "$install_choice" ]; then
                        install_nginx
                    else
                        continue
                    fi
                fi
                setup_https_website
                ;;
            3)
                detect_os
                upgrade_http_to_https
                ;;
            4)
                detect_os
                show_detection_menu
                ;;
            5)
                print_message "$GREEN" "感谢使用！"
                exit 0
                ;;
            *)
                print_message "$RED" "无效选择，请重试"
                ;;
        esac
    done
}

# ========================================
#            主程序入口
# ========================================

main() {
    # 检查是否以root权限运行
    if [ "$EUID" -ne 0 ]; then
        print_message "$RED" "请使用sudo或root权限运行此脚本"
        exit 1
    fi

    # 显示欢迎信息
    clear
    print_message "$GREEN" "========================================"
    print_message "$GREEN" "    Website Easy Install v$SCRIPT_VERSION"
    print_message "$GREEN" "========================================"
    print_message "$GREEN" "  HTTP/HTTPS网站一键部署工具"
    print_message "$GREEN" "  支持Let's Encrypt自动SSL证书"
    print_message "$GREEN" "========================================"
    echo ""

    # 显示主菜单
    show_main_menu
}

# 运行主程序
main "$@"