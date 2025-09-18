# Website Easy Install

一键部署 HTTP/HTTPS 网站，自动配置 Nginx 和 Let's Encrypt SSL 证书。

## 功能特性

- ✅ **HTTP/HTTPS 网站一键部署**
- ✅ **自动申请和续期 Let's Encrypt SSL 证书**
- ✅ **系统问题自动检测与修复**
- ✅ **支持多域名配置**
- ✅ **HTTP 站点升级 HTTPS**

## 一键安装

### 使用 curl（推荐）
```bash
curl -sSL https://raw.githubusercontent.com/wade0317/quick-ssl-deploy/master/quick-ssl-deploy.sh | sudo bash
```

### 使用 wget
```bash
wget -qO- https://raw.githubusercontent.com/wade0317/quick-ssl-deploy/master/quick-ssl-deploy.sh | sudo bash
```

### 下载后运行

如果需要先查看脚本内容：

```bash
# 下载脚本
curl -O https://raw.githubusercontent.com/wade0317/quick-ssl-deploy/master/quick-ssl-deploy.sh
# 或
wget https://raw.githubusercontent.com/wade0317/quick-ssl-deploy/master/quick-ssl-deploy.sh

# 查看脚本（可选）
less quick-ssl-deploy.sh

# 运行脚本
chmod +x quick-ssl-deploy.sh
sudo ./quick-ssl-deploy.sh
```

## 使用方法

### 选择功能

```
========================================
    Website Easy Install v2.0
========================================

1) 安装HTTP网站
2) 安装HTTPS网站（自动SSL）
3) 将现有HTTP升级为HTTPS
4) 系统检测与问题修复
5) 退出

请选择 [1-5]:
```

## 系统要求

- **操作系统**: Ubuntu/Debian 或 CentOS/RHEL
- **权限**: root 或 sudo 权限
- **端口**: 80 和 443 端口需在防火墙开放

## 主要功能说明

### 🌐 HTTP 网站部署
- 自动安装配置 Nginx
- 创建网站目录和默认首页
- 支持多域名绑定

### 🔒 HTTPS 网站部署
- 自动申请 Let's Encrypt SSL 证书
- 配置 Nginx SSL
- 设置证书自动续期（每月自动执行）
- 支持多域名 SAN 证书

### ⬆️ HTTP 升级 HTTPS
- 自动检测现有 HTTP 站点
- 保留原有配置升级为 HTTPS
- 自动备份原配置文件

### 🔧 系统检测与修复
自动检测并修复以下问题：
- **Nginx 未安装**: 自动安装并配置
- **SELinux 问题**: 配置正确的上下文或调整模式
- **防火墙配置**: 自动开放 80/443 端口
- **云平台检测**: 提醒配置安全组规则

## 支持的系统

- Ubuntu 16.04/18.04/20.04/22.04
- Debian 9/10/11
- CentOS 6/7/8
- RHEL 6/7/8
- Amazon Linux
- 阿里云/腾讯云/AWS/GCP 等云平台

## 常见问题

### 证书申请失败
- 确保域名已正确解析到服务器 IP
- 确保 80 端口可以访问
- 检查防火墙设置

### SELinux 导致 403 错误
运行脚本选择 `4) 系统检测与问题修复`，自动修复 SELinux 配置。

### 云平台防火墙
除了系统防火墙，还需在云平台控制台的安全组中开放 80 和 443 端口。

## 证书续期

脚本会自动设置 cron 定时任务，每月自动续期证书，无需手动干预。

续期日志位置：`/var/log/renew_cert.log`

## License

MIT

## 致谢

- [Let's Encrypt](https://letsencrypt.org)
- [acme-tiny](https://github.com/diafygi/acme-tiny)