#!/bin/bash

# ================================
#        Konfigurasi Warna
# ================================
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
NC='\e[0m'

# ================================
#        Variabel Global
# ================================
CHATID="6617783693"
KEY="6751589620:AAHwjP6dzZhuqeyUOdYFc6742Q1YUVF1EjM"
URL="https://api.telegram.org/bot$KEY/sendMessage"
REPO="https://raw.githubusercontent.com/ianlunatix/iandian/main/"
IP=$(curl -s ipv4.icanhazip.com)

# ================================
#        Fungsi Utama
# ================================

# Validasi Hak Akses Root
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} Harap jalankan skrip ini sebagai root!"
    exit 1
  fi
}

# Validasi Sistem Operasi
check_os() {
  OS=$(grep -w ID /etc/os-release | awk -F= '{print $2}' | tr -d '"')
  if [[ $OS != "ubuntu" && $OS != "debian" ]]; then
    echo -e "${ERROR} Sistem operasi tidak didukung! Hanya mendukung Ubuntu/Debian."
    exit 1
  else
    OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | awk -F= '{print $2}' | tr -d '"')
    echo -e "${OK} Sistem operasi terdeteksi: ${Green}${OS_NAME}${NC}"
  fi
}

# Validasi Arsitektur
check_architecture() {
  ARCH=$(uname -m)
  if [[ $ARCH != "x86_64" ]]; then
    echo -e "${ERROR} Arsitektur tidak didukung! Hanya mendukung x86_64."
    exit 1
  else
    echo -e "${OK} Arsitektur didukung: ${Green}${ARCH}${NC}"
  fi
}

# Validasi IP
check_ip() {
  if [[ -z $IP ]]; then
    echo -e "${ERROR} IP Address tidak terdeteksi!"
    exit 1
  else
    echo -e "${OK} IP Address terdeteksi: ${Green}${IP}${NC}"
  fi
}

# Persiapan Direktori dan File
prepare_directories() {
  echo -e "${OK} Menyiapkan direktori..."
  mkdir -p /etc/xray /var/log/xray /var/lib/LT
  touch /etc/xray/ipvps /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log
  touch /var/log/xray/accessvle.log /var/log/xray/errorvle.log
  touch /var/log/xray/accessvme.log /var/log/xray/errorvme.log
  touch /var/log/xray/accesstro.log /var/log/xray/errortro.log  
  chown www-data:www-data /var/log/xray
  chmod +x /var/log/xray
  echo "$IP" > /etc/xray/ipvps

}

# Unduh File Konfigurasi
download_files() {
  echo -e "${OK} Mengunduh file konfigurasi..."
  curl -s -o /usr/bin/xray https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
  chmod +x /usr/bin/xray
}

# Perhitungan RAM
calculate_ram() {
  while IFS=":" read -r key value; do
    case $key in
      "MemTotal") ((mem_total=${value/kB}));;
      "MemFree" | "Buffers" | "Cached" | "SReclaimable") ((mem_used+=${value/kB}));;
    esac
  done < /proc/meminfo
  mem_used="$((mem_total - mem_used))"
  Ram_Usage=$((mem_used / 1024))
  Ram_Total=$((mem_total / 1024))
  echo -e "${OK} RAM Terpakai: ${Ram_Usage}MB / Total RAM: ${Ram_Total}MB"
}

# Kirim Notifikasi ke Telegram
send_notification() {
  curl -s -X POST "$URL" -d chat_id="$CHATID" -d text="Skrip sedang meng install di server VPS dengan IP: $IP" >/dev/null
  echo -e "${OK} Notifikasi terkirim ke Telegram."
}

# ================================
#        Eksekusi Utama
# ================================

main() {
  clear
  echo -e "${YELLOW}----------------------------------------------------------${NC}"
  echo -e "${BLUE}               Lunatic Tunneling Installer${NC}"
  echo -e "${YELLOW}----------------------------------------------------------${NC}"
  sleep 2
  
  # Langkah-langkah instalasi
  check_root
  check_os
  check_architecture
  check_ip
  prepare_directories
  download_files
  calculate_ram
  send_notification

  echo -e "${OK} Instalasi selesai!"
}

main

# Fungsi deteksi OS dan versi
detect_os() {
  OS=$(grep -w ID /etc/os-release | head -n1 | awk -F= '{print $2}' | tr -d '"')
  VERSION_ID=$(grep -w VERSION_ID /etc/os-release | awk -F= '{print $2}' | tr -d '"')
  OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | awk -F= '{print $2}' | tr -d '"')

  echo -e "${OK} Deteksi OS: ${Green}${OS_NAME}${FONT}"
}

# Fungsi setup awal
first_setup() {
  echo -e "${OK} Mengatur zona waktu ke Asia/Jakarta..."
  timedatectl set-timezone Asia/Jakarta

  echo -e "${OK} Mengatur iptables-persistent untuk autosave..."
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
}

# Fungsi instalasi HAProxy berdasarkan OS
install_haproxy() {
  case $OS in
  ubuntu)
    case $VERSION_ID in
    "20.04")
      echo -e "${OK} Instalasi HAProxy 2.0 untuk ${Green}Ubuntu $VERSION_ID${FONT}..."
      apt update -y
      apt-get install --no-install-recommends -y software-properties-common
      add-apt-repository ppa:vbernat/haproxy-2.0 -y
      apt-get install -y haproxy=2.0.*
      ;;
    "22.04")
      echo -e "${OK} Instalasi HAProxy 2.4 untuk ${Green}Ubuntu $VERSION_ID${FONT}..."
      apt update -y
      apt-get install --no-install-recommends -y software-properties-common
      add-apt-repository ppa:vbernat/haproxy-2.4 -y
      apt-get install -y haproxy=2.4.*
      ;;
    "24.04")
      echo -e "${OK} Instalasi HAProxy 2.9 untuk ${Green}Ubuntu $VERSION_ID${FONT}..."
      apt update -y
      apt-get install --no-install-recommends -y software-properties-common
      add-apt-repository ppa:vbernat/haproxy-2.9 -y
      apt-get install -y haproxy=2.9.*
      ;;
    *)
      print_error "Versi Ubuntu $VERSION_ID tidak didukung."
      exit 1
      ;;
    esac
    ;;
  debian)
    case $VERSION_ID in
    "10")
      echo -e "${OK} Instalasi HAProxy 1.8 untuk ${Green}Debian $VERSION_ID${FONT}..."
      curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg |
        gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
      echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports main" >/etc/apt/sources.list.d/haproxy.list
      apt update -y
      apt-get install -y haproxy=1.8.*
      ;;
    "11")
      echo -e "${OK} Instalasi HAProxy 2.4 untuk ${Green}Debian $VERSION_ID${FONT}..."
      curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg |
        gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
      echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bullseye-backports main" >/etc/apt/sources.list.d/haproxy.list
      apt update -y
      apt-get install -y haproxy=2.4.*
      ;;
    "12")
      echo -e "${OK} Instalasi HAProxy 2.6 untuk ${Green}Debian $VERSION_ID${FONT}..."
      curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg |
        gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
      echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports main" >/etc/apt/sources.list.d/haproxy.list
      apt update -y
      apt-get install -y haproxy=2.6.*
      ;;
    *)
      print_error "Versi Debian $VERSION_ID tidak didukung."
      exit 1
      ;;
    esac
    ;;
  *)
    print_error "OS $OS tidak didukung."
    exit 1
    ;;
  esac
}

# ======= Eksekusi =======

HAPROXY_INSTALLER() {
  clear
  echo -e "\e[92;1m Mulai instalasi HAProxy..."
  detect_os
  first_setup
  install_haproxy
  echo -e "\e[92;1m Instalasi HAProxy selesai."
}

HAPROXY_INSTALLER


function nginx_install() {
  # Deteksi OS dan versi
  OS=$(grep -w ID /etc/os-release | head -n1 | awk -F= '{print $2}' | tr -d '"')
  OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | awk -F= '{print $2}' | tr -d '"')

  # Cetak status instalasi
  echo -e "\e[96;1m Setup nginx untuk OS ${Green}$OS_NAME${FONT}"

  if [[ "$OS" == "ubuntu" ]]; then
    echo -e "${OK} Menginstal nginx di Ubuntu..."
    apt install nginx -y
    echo -e "\e[92;1m Nginx berhasil diinstal pada Ubuntu."

  elif [[ "$OS" == "debian" ]]; then
    echo -e "${OK} Menginstal nginx di Debian..."
    apt install nginx -y
    echo -e "\e[92;1m Nginx berhasil diinstal pada Debian."

  else
    echo -e "${ERROR} OS Anda (${YELLOW}$OS_NAME${FONT}) tidak didukung untuk instalasi nginx."
    exit 1
  fi
}

function base_package() {
clear
echo -e "\e[96;1m Menginstall Packet Yang Dibutuhkan \e[0m"
apt install zip pwgen openssl netcat socat cron bash-completion -y
apt install figlet -y
apt update -y
apt upgrade -y
apt dist-upgrade -y
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v
apt install ntpdate -y
ntpdate pool.ntp.org
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
echo -e "\e[92;1m Packet Yang Dibutuhkan"
}

function pasang_domain() {
  clear
  echo -e "    \e[91;1m================================\e[0m"
  echo -e "    \e[1;32m   Pilih Jenis Domain di Bawah Ini   \e[0m"
  echo -e "    \e[91;1m================================\e[0m"
  echo -e "    \e[1;32m 1).\e[97;1m Domain Sendiri"
  echo -e "    \e[1;32m 2).\e[97;1m Domain (Random)"
  echo -e "    \e[91;1m================================\e[0m"
  read -p "   Silakan pilih angka 1-2 atau tombol lain (Random) : " host
  echo ""

  case $host in
    1)
      # Pilih domain khusus
      clear
      echo ""
      echo -e "    \e[91;1m================================\e[0m"
      echo -e "    \e[1;32m      INPUT YOUR SUBDOMAINS    \e[0m"
      echo -e "    \e[91;1m================================\e[0m"
      echo ""
      read -p "   MASUKKAN DOMAIN ANDA: " host1
      if [[ -z "$host1" ]]; then
        echo -e "   ${RED}[ERROR]${NC} Domain tidak boleh kosong!"
        return 1
      fi
      echo "IP=" >> /var/lib/LT/ipvps.conf
      echo "$host1" > /etc/xray/domain
      echo "$host1" > /root/domain
      echo -e "   ${Green}[OK]${NC} Domain berhasil disimpan: $host1"
      ;;
    2)
      # Gunakan domain acak
      echo -e "   ${Green}[OK]${NC} Menggunakan domain acak..."
      wget ${REPO}domains/cf.sh -O /root/cf.sh && chmod +x /root/cf.sh && /root/cf.sh
      rm -f /root/cf.sh
      ;;
    *)
      # Pilihan default (domain acak)
      echo -e "\e[96;1m Domain/Subdomain Acak akan digunakan."
      wget ${REPO}domains/cf.sh -O /root/cf.sh && chmod +x /root/cf.sh && /root/cf.sh
      rm -f /root/cf.sh
      ;;
  esac
  echo -e "\n${Green}[OK]${NC} Domain telah diatur."
  sleep 2
}

function restart_system() {
  ipsaya=$(curl -s ipv4.icanhazip.com)
  USRSC=$(wget -qO- https://raw.githubusercontent.com/ianlunatix/vps_access/main/ipmain | grep $ipsaya | awk '{print $2}')
  EXPSC=$(wget -qO- https://raw.githubusercontent.com/ianlunatix/vps_access/main/ipmain | grep $ipsaya | awk '{print $3}')
  TIMEZONE=$(date '+%H:%M:%S') # Format waktu 24 jam
  DATE=$(date '+%d %b %Y')     # Format tanggal yang lebih rapi
  DOMAIN=$(cat /etc/xray/domain || echo "Domain not set") # Ambil domain dari file atau default jika tidak ditemukan

  # Pesan notifikasi
  TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>ID       : </code><code>$USRSC</code>
<code>Domain   : </code><code>$DOMAIN</code>
<code>Date     : </code><code>$DATE</code>
<code>Time     : </code><code>$TIMEZONE</code>
<code>IP VPS   : </code><code>$ipsaya</code>
<code>Exp Sc   : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"

  # Inline keyboard untuk pesan Telegram
  INLINE_KEYBOARD='{
    "inline_keyboard": [
      [
        {"text": "ᴏʀᴅᴇʀ", "url": "https://t.me/ian_khvicha"},
        {"text": "Contack", "url": "https://wa.me/6285955333616"}
      ]
    ]
  }'

  # Kirim notifikasi ke Telegram
  curl -s --max-time $TIMES \
    -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html&reply_markup=$INLINE_KEYBOARD" \
    $URL >/dev/null

  # Restart sistem
  echo -e "\n${Green}[OK]${NC} Mengirim notifikasi ke Telegram."
}

function pasang_ssl() {
  clear
  echo -e "\e[96;1m Memasang SSL pada Domain"

  # Hapus file SSL lama
  rm -f /etc/xray/xray.key /etc/xray/xray.crt

  # Baca domain
  domain=$(cat /root/domain 2>/dev/null || echo "DomainNotSet")
  if [[ $domain == "DomainNotSet" ]]; then
    print_error "Domain tidak ditemukan. Pastikan domain telah diatur!"
    exit 1
  fi

  # Berhenti semua proses yang menggunakan port 80
  STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
  if [[ ! -z $STOPWEBSERVER ]]; then
    systemctl stop $STOPWEBSERVER
  fi

  # Pastikan Nginx dihentikan
  systemctl stop nginx

  # Persiapan direktori untuk acme.sh
  rm -rf /root/.acme.sh
  mkdir -p /root/.acme.sh

  # Unduh dan instal acme.sh
  curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
  chmod +x /root/.acme.sh/acme.sh
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade

  # Konfigurasi CA default untuk Let's Encrypt
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  # Terbitkan sertifikat SSL
  /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
  if [[ $? -ne 0 ]]; then
    print_error "Gagal menerbitkan sertifikat SSL untuk domain $domain."
    exit 1
  fi

  # Instal sertifikat SSL
  /root/.acme.sh/acme.sh --installcert -d "$domain" \
    --fullchainpath /etc/xray/xray.crt \
    --keypath /etc/xray/xray.key --ecc

  if [[ $? -eq 0 ]]; then
    chmod 600 /etc/xray/xray.key /etc/xray/xray.crt
    echo -e "\e[92;1m SSL Certificate berhasil dipasang untuk domain $domain"
  else
    print_error "Gagal memasang sertifikat SSL untuk domain $domain."
    exit 1
  fi
}

function make_folder_xray() {
    # Direktori utama untuk aplikasi Lunatic
    local base_dir="/etc/lunatic"
    
    # Daftar direktori yang perlu dibuat
    local directories=(
        "$base_dir"
        "$base_dir/vmess/ip"
        "$base_dir/vless/ip"
        "$base_dir/trojan/ip"
        "$base_dir/ssh/ip"
        "$base_dir/vmess/detail"
        "$base_dir/vless/detail"
        "$base_dir/trojan/detail"
        "$base_dir/shadowsocks/detail"
        "$base_dir/ssh/detail"
        "$base_dir/noobzvpns/detail"
        "$base_dir/vmess/usage"
        "$base_dir/vless/usage"
        "$base_dir/shadowsocks/usage"
        "$base_dir/trojan/usage"
        "$base_dir/bot"
        "$base_dir/bot/telegram"
        "$base_dir/bot/notif"
        "/usr/bin/xray"
        "/var/log/xray"
        "/var/www/html"
        "/usr/sbin/local"
        "/usr/local/sbin"
        "/usr/bin"
    )

    # Membuat direktori yang diperlukan
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done

    # Menyiapkan file yang diperlukan
    local files=(
        "/etc/xray/domain"
        "/var/log/xray/access.log"
        "/var/log/xray/error.log"
        "$base_dir/vmess/.vmess.db"
        "$base_dir/vless/.vless.db"
        "$base_dir/trojan/.trojan.db"
        "$base_dir/ssh/.ssh.db"
        "$base_dir/bot/.bot.db"
        "$base_dir/bot/notif/key"
        "$base_dir/bot/notif/id"
    )

    # Membuat file jika belum ada
    for file in "${files[@]}"; do
        touch "$file"
    done

    # Menambahkan konten default pada file .db
    echo "& plugin Account" >> "$base_dir/vmess/.vmess.db"
    echo "& plugin Account" >> "$base_dir/vless/.vless.db"
    echo "& plugin Account" >> "$base_dir/trojan/.trojan.db"
    echo "& plugin Account" >> "$base_dir/ssh/.ssh.db"

    # Memberikan izin eksekusi pada direktori log xray
    chmod +x "/var/log/xray"
}


function install_xray() {
  clear
  echo -e "\e[96;1m Memasang Core Xray Versi Terbaru"

  mkdir -p /run/xray

  # Direktori untuk domain socket
  domainSock_dir="/run/xray"
  if [[ ! -d $domainSock_dir ]]; then
    mkdir -p $domainSock_dir
    chown www-data:www-data $domainSock_dir
  fi

  # Dapatkan versi terbaru Xray dari GitHub API
  latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | sed -E 's/.*"v(.*)".*/\1/')"
  
  if [[ -z $latest_version ]]; then
    print_error "Gagal mendapatkan versi terbaru Xray dari GitHub."
    exit 1
  fi

  # Instal Xray
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

  # Unduh file konfigurasi config.json
  wget -O /etc/xray/config.json "${REPO}xrayv2ray/config.json" >/dev/null 2>&1
  
  # config json only
  wget -O /etc/xray/vme.json "${REPO}xrayv2ray/vme.json" >/dev/null 2>&1
  wget -O /etc/xray/vle.json "${REPO}xrayv2ray/vle.json" >/dev/null 2>&1
  wget -O /etc/xray/tro.json "${REPO}xrayv2ray/tro.json" >/dev/null 2>&1
  wget -O /etc/systemd/system/runn.service "${REPO}xrayv2ray/runn.service" >/dev/null 2>&1
  
  domain=$(cat /etc/xray/domain 2>/dev/null || echo "DomainNotSet")
  #IPVS=$(cat /etc/xray/ipvps 2>/dev/null || echo "IPNotSet")

  # Verifikasi domain
  if [[ $domain == "DomainNotSet" ]]; then
    print_error "Domain tidak ditemukan. Pastikan domain sudah diatur."
    sleep 2    
  fi

  # Simpan informasi lokasi dan ISP
  curl -s ipinfo.io/city > /etc/xray/city
  curl -s ipinfo.io/org | cut -d " " -f 2-10 > /etc/xray/isp
  # ip vps 
  IP=$(curl -s ipv4.icanhazip.com)
  
  # Konfigurasi HAProxy dan Nginx
  echo -e "\e[96;1m Mengunduh dan Memasang Konfigurasi\e[0m"
  wget -O /etc/haproxy/haproxy.cfg "${REPO}xrayv2ray/haproxy.cfg" >/dev/null 2>&1
  wget -O /etc/nginx/conf.d/xray.conf "${REPO}xrayv2ray/xray.conf" >/dev/null 2>&1
  wget -O /etc/squid/squid.conf "${REPO}xrayv2ray/squid.conf" >/dev/null 2>&1
  
  sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
  sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
  sed -i "s/xxx/${IP}/g" /etc/squid/squid.conf

  # nginx sshopenvpn
  curl -s ${REPO}sshopenvpn/nginx.conf > /etc/nginx/nginx.conf
  cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem

  # Atur izin file
  chmod 600 /etc/haproxy/hap.pem
  chmod +x /etc/systemd/system/runn.service

  # Konfigurasi layanan systemd untuk Xray
  echo -e "\e[96;1m Menyiapkan Layanan Systemd untuk Xray\e[0m"
  rm -rf /etc/systemd/system/xray.service.d
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  # Reload systemd dan aktifkan layanan
  systemctl daemon-reload
  systemctl enable xray
  systemctl restart xray

# config json vmess
  cat > /etc/systemd/system/vmejs.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vme.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  # Reload systemd dan aktifkan layanan
  systemctl daemon-reload
  systemctl enable vmejs
  systemctl restart vmejs

# config json vless
  cat > /etc/systemd/system/vlejs.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vle.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  # Reload systemd dan aktifkan layanan
  systemctl daemon-reload
  systemctl enable vlejs
  systemctl restart vlejs

# config json trojan
  cat > /etc/systemd/system/trojs.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/tro.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  # Reload systemd dan aktifkan layanan
  systemctl daemon-reload
  systemctl enable trojs
  systemctl restart trojs


  echo -e "\e[92;1m Core Xray ${latest_version} berhasil dipasang dan dikonfigurasi."
}


function INSTALL_SSH_PASSWORD(){
clear
echo -e "\e[96;1m Memasang Password SSH\e[0m"
wget -O /etc/pam.d/common-password "${REPO}sshopenvpn/password"
chmod +x /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
cat > /etc/rc.local <<-END
exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
echo -e "\e[92;1m Password SSH"
}
function INSTALL_LIMIT() {
  clear
  echo -e "\e[96;1m Memasang Quota & Service Xray\e[0m"

  # Unduh script limit.sh dan jalankan
  wget -q https://raw.githubusercontent.com/ianlunatix/iandian/main/limit_access/limit.sh -O limit.sh
  if [[ -f "limit.sh" ]]; then
    chmod +x limit.sh
    ./limit.sh
    rm -f limit.sh
  else
    print_error "Gagal mengunduh limit.sh"
    sleep 2
    clear
  fi

  # Unduh limit-ip dan atur izin
  wget -q -O /usr/bin/limit-ip "${REPO}limit_access/limit-ip"
  if [[ -f "/usr/bin/limit-ip" ]]; then
    chmod +x /usr/bin/limit-ip
    sed -i 's/\r//' /usr/bin/limit-ip
  else
    print_error "Gagal mengunduh limit-ip"
    sleep 2
    clear
  fi

  # Buat dan aktifkan layanan systemd untuk vmip
  cat > /etc/systemd/system/vmip.service << EOF
[Unit]
Description=Limit IP Service - VMIP
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart vmip
  systemctl enable vmip

  # Buat dan aktifkan layanan systemd untuk vlip
  cat > /etc/systemd/system/vlip.service << EOF
[Unit]
Description=Limit IP Service - VLIP
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart vlip
  systemctl enable vlip

  # Buat dan aktifkan layanan systemd untuk trip
  cat > /etc/systemd/system/trip.service << EOF
[Unit]
Description=Limit IP Service - TRIP
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart trip
  systemctl enable trip

  echo -e "\e[92;1m Quota dan Service Xray berhasil dipasang!\e[0m"
}


function INSTALL_BADVPN() {
  clear
  echo -e "\e[96;1m Memasang BadVPN Service\e[0m"

  # Buat direktori tujuan
  mkdir -p /usr/local/lunatic/

  # Unduh file binary udp-mini
  wget -q -O /usr/local/lunatic/udp-mini "${REPO}badvpn/udp-mini"
  if [[ -f "/usr/local/lunatic/udp-mini" ]]; then
    chmod +x /usr/local/lunatic/udp-mini
  else
    print_error "Gagal mengunduh udp-mini"
    exit 1
  fi

  # Unduh file layanan systemd untuk udp-mini
  for i in {1..3}; do
    wget -q -O /etc/systemd/system/udp-mini-${i}.service "${REPO}badvpn/udp-mini-${i}.service"
    if [[ ! -f "/etc/systemd/system/udp-mini-${i}.service" ]]; then
      print_error "Gagal mengunduh file service udp-mini-${i}.service"
      exit 1
    fi
  done

  # Konfigurasi dan aktifkan layanan udp-mini
  for i in {1..3}; do
    systemctl daemon-reload
    systemctl disable udp-mini-${i} >/dev/null 2>&1
    systemctl stop udp-mini-${i} >/dev/null 2>&1
    systemctl enable udp-mini-${i}
    systemctl start udp-mini-${i}
    if systemctl is-active --quiet udp-mini-${i}; then
      echo -e "\e[92;1m Layanan udp-mini-${i} aktif"
    else
      print_error "Gagal mengaktifkan layanan udp-mini-${i}"
    fi
  done

  echo -e "\e[92;1m BadVPN berhasil dipasang!\e[0m"
}

function ins_SSHD(){
clear
echo -e "\e[96;1m Memasang SSHD\e[0m"
wget -q -O /etc/ssh/sshd_config "${REPO}sshopenvpn/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
echo -e "\e[92;1m SSHD\e[0m"
}

function ins_dropbear(){
clear
echo -e "\e[96;1m Menginstall Dropbear\e[0m"
apt-get install dropbear -y > /dev/null 2>&1
wget -q -O /etc/default/dropbear "${REPO}sshopenvpn/dropbear.conf"
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
echo -e "\e[92;1m Dropbear"
}

function ins_vnstat() {
  clear
  echo -e "\e[96;1m Menginstall Vnstat\e[0m"

  # Instal paket yang diperlukan
  apt -y install vnstat libsqlite3-dev > /dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    print_error "Gagal menginstal dependensi"
    sleep 2
    clear
  fi

  # Restart layanan vnstat bawaan
  systemctl restart vnstat
  systemctl enable vnstat

  # Unduh dan instal Vnstat versi terbaru
  wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
  if [[ ! -f "vnstat-2.6.tar.gz" ]]; then
    print_error "Gagal mengunduh vnstat-2.6.tar.gz"
    sleep 2
    clear
  fi

  tar -xzf vnstat-2.6.tar.gz
  cd vnstat-2.6 || exit
  ./configure --prefix=/usr --sysconfdir=/etc && make && make install
  if [[ $? -ne 0 ]]; then
    print_error "Gagal menginstal vnstat versi 2.6"
    sleep 2
    clear
  fi
  cd ..

  # Konfigurasi vnstat untuk menggunakan antarmuka jaringan yang benar
  vnstat -u -i "$NET"
  sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
  chown vnstat:vnstat /var/lib/vnstat -R

  # Restart layanan untuk menerapkan perubahan
  systemctl restart vnstat

  # Periksa status layanan
  systemctl status vnstat | grep "active (running)" > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echo -e "\e[92;1m Vnstat berhasil diinstal dan berjalan"
  else
    print_error "Gagal menjalankan vnstat"
  fi

  # Bersihkan file instalasi
  rm -f vnstat-2.6.tar.gz
  rm -rf vnstat-2.6
}

function ins_openvpn(){
clear
echo -e "\e[96;1m Menginstall OpenVPN\e[0m"
apt install openvpn -y
wget ${REPO}sshopenvpn/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
echo -e "\e[92;1m OpenVPN"
}

function ins_backup() {
  clear
  echo -e "\e[96;1m Memasang Backup Server\e[0m"

  # Instal Rclone
  apt install rclone -y
  if [[ $? -ne 0 ]]; then
    print_error "Gagal menginstal Rclone"
    sleep 2
    clear
  fi

  # Konfigurasi Rclone
  printf "q\n" | rclone config
  wget -q -O /root/.config/rclone/rclone.conf "${REPO}backupsdata/rclone.conf"
  if [[ ! -f /root/.config/rclone/rclone.conf ]]; then
    print_error "Gagal mengunduh file konfigurasi Rclone"
    sleep 2
    clear
  fi

  # Instal Wondershaper
  cd /bin
  git clone https://github.com/magnific0/wondershaper.git
  if [[ ! -d wondershaper ]]; then
    print_error "Gagal mengkloning repositori Wondershaper"
    sleep 2
    clear
  fi
  cd wondershaper
  sudo make install
  cd
  rm -rf /bin/wondershaper

  # Buat file kosong untuk file backup
  touch /home/files

  # Instal msmtp dan dependensi
  apt install msmtp-mta ca-certificates bsd-mailx -y
  if [[ $? -ne 0 ]]; then
    print_error "Gagal menginstal msmtp dan dependensi"
    sleep 2
    clear
  fi

  # Konfigurasi msmtp
  cat <<EOF > /etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user mezzqueen293@gmail.com
from mezzqueen293@gmail.com
password YOUR_EMAIL_PASSWORD
logfile ~/.msmtp.log
EOF

  # Ubah kepemilikan dan izin file konfigurasi msmtp
  chown www-data:www-data /etc/msmtprc
  chmod 600 /etc/msmtprc

  # Unduh dan jalankan file IP server
  wget -q -O /etc/ipserver "${REPO}sshopenvpn/ipserver"
  if [[ ! -f /etc/ipserver ]]; then
    print_error "Gagal mengunduh file ipserver"
    sleep 2
    clear
  fi
  bash /etc/ipserver

  echo -e "\e[92;1m Backup Server berhasil diinstal\e[0m"
}

function ins_swab(){
clear
echo -e "\e[96;1m 1GB swapp \e[0m"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${REPO}bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
echo -e "\e[92;1m Swap 1 G\e[0m"
}


function ins_Fail2ban(){
clear
echo -e "\e[96;1m Menginstall Fail2ban\e[0m"
if [ -d '/usr/local/ddos' ]; then
echo; echo; echo "Please un-install the previous version first"
exit 0
else
mkdir /usr/local/ddos
fi
clear
echo -e "\e[92;1m fail2ban no DDOS\e[0m"
}

function INSTALL_SSHBANNER() {
echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
wget -O /etc/lunatic.txt "${REPO}issue.net"
echo -e "\e[92;1m banner ssh"
}

function ins_epro(){
clear
echo -e "\e[96;1m Menginstall ePro WebSocket Proxy\e[0m"
wget -O /usr/bin/ws "${REPO}sshopenvpn/ws" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "${REPO}sshopenvpn/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "${REPO}sshopenvpn/ws.service" >/dev/null 2>&1
chmod +x /etc/systemd/system/ws.service
chmod +x /usr/bin/ws
chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}lttunnel" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
echo -e "\e[92;1m ePro WebSocket Proxy"
}
function ins_restart(){
clear
echo -e "\e[96;1m Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws
systemctl enable --now fail2ban
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
echo -e "\e[92;1m All Packet\e[0m"
}
function menu(){
clear
echo -e "\e[96;1m Memasang Menu Packet\e[0m"
      wget ${REPO}features/LunatiX_sh
      unzip LunatiX_sh
      chmod +x menu/*
      mv menu/* /usr/local/sbin
      rm -rf menu
      rm -rf LunatiX_sh

echo -e "\e[96;1m Memasang Menu Packet\e[0m"
      wget ${REPO}features/LunatiX_py
      unzip LunatiX_py
      chmod +x menu/*
      mv menu/* /usr/bin
      rm -rf menu
      rm -rf LunatiX_py

}
function profile(){
clear
cat >/root/.profile <<EOF
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
menu
EOF


cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

chmod 644 /root/.profile
cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart
cat >/home/daily_reboot <<-END
5
END
cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
chmod +x /etc/rc.local
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ $AUTOREB -gt $SETT ]; then
TIME_DATE="PM"
else
TIME_DATE="AM"
fi
echo -e "\e[92;1m Menu Packet \e[0m"
}
function enable_services(){
clear
echo -e "\e[96;1m Enable Service\e[0m"
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local
systemctl enable --now cron
systemctl enable --now netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart cron
systemctl restart haproxy
clear
}
function instal(){
clear
first_setup
nginx_install
base_package
make_folder_xray
pasang_domain
password_default
pasang_ssl
install_xray
INSTALL_SSH_PASSWORD
INSTALL_LIMIT
INSTALL_BADVPN
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
INSTALL_SSHBANNER
ins_epro
ins_restart
menu
profile
enable_services
restart_system
}
instal
echo ""


history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
clear
echo -e ""
echo -e ""
echo -e "\033[96m==========================\033[0m"
echo -e "\033[92m         INSTALL SUCCES\033[0m"
echo -e "\033[96m==========================\033[0m"
echo -e ""
sleep 2
clear
echo -e "\033[93;1m Wait inn 4 sec...\033[0m"
sleep 4
clear
echo ""
read -p "Press [ Enter ]  TO REBOOT"
reboot
