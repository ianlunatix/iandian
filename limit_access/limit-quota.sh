REPO="https://raw.githubusercontent.com/ianlunatix/iandian/main/"
wget -q -O /etc/systemd/system/limitvmess.service "${REPO}limit_access/limitvmess.service" && chmod +x limitvmess.service >/dev/null 2>&1
wget -q -O /etc/systemd/system/limitvless.service "${REPO}limit_access/limitvless.service" && chmod +x limitvless.service >/dev/null 2>&1
wget -q -O /etc/systemd/system/limittrojan.service "${REPO}limit_access/limittrojan.service" && chmod +x limittrojan.service >/dev/null 2>&1
wget -q -O /etc/systemd/system/limitshadowsocks.service "${REPO}limit_access/limitshadowsocks.service" && chmod +x limitshadowsocks.service >/dev/null 2>&1
 # // service quota xray
wget -q -O /etc/xray/quota-vme "${REPO}limit_access/quota-vme" >/dev/null 2>&1
wget -q -O /etc/xray/quota-vle "${REPO}limit_access/quota-vle" >/dev/null 2>&1
wget -q -O /etc/xray/quota-tro "${REPO}limit_access/quota-tro" >/dev/null 2>&1
wget -q -O /etc/xray/quota-ssr "${REPO}limit_access/quota-ssr" >/dev/null 2>&1
chmod +x /etc/xray/quota-vme
chmod +x /etc/xray/quota-vle
chmod +x /etc/xray/quota-tro
chmod +x /etc/xray/quota-ssr
systemctl daemon-reload
systemctl enable --now limitvmess
systemctl enable --now limitvless
systemctl enable --now limittrojan
systemctl enable --now limitshadowsocks