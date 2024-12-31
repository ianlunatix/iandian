#!/bin/bash
# =========================================
# Edition : Stable Edition V4.41
# Authorz  : Lunatic Tunneling
# (e) Edit => 2024
# =========================================
clear
domain=$(cat /etc/xray/domain)
IP=$( curl -s ifconfig.me )
apt install haproxy -y
 wget -q -O /etc/squid/squid.conf "https://raw.githubusercontent.com/iandean/main/sshopenvpn/squid.conf" >/dev/null 2>&1
    wget -O /etc/haproxy/haproxy.cfg "https://raw.githubusercontent.com/iandean/main/xray/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "https://raw.githubusercontent.com/iandean/main/xray/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    sed -i "s/xxx/${IP}/g" /etc/squid/squid.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
    echo ""
