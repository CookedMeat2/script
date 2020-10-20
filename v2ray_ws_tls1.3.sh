#!/bin/bash
function blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
function green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
function red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
function yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

function check_os(){
green
green
green " --------------------------------------------------------"
green "系统支持检测"
sleep 5
if [[ -f /etc/redhat-release ]]; then
    release="centos"
    systemPackage="yum"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
fi
if [ "$release" == "centos" ]; then
    if  [ -n "$(grep ' 6\.' /etc/redhat-release)" ] ;then
    red "====================="
    red "当前系统不受支持"
    red "====================="
    exit
    fi
    if  [ -n "$(grep ' 5\.' /etc/redhat-release)" ] ;then
    red "====================="
    red "当前系统不受支持"
    red "====================="
    exit
    fi
    rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm >/dev/null 2>&1
    green "开始安装nginx编译依赖"
    yum install -y libtool perl-core zlib-devel gcc pcre* >/dev/null 2>&1
elif [ "$release" == "ubuntu" ]; then
    if  [ -n "$(grep ' 14\.' /etc/os-release)" ] ;then
    red "====================="
    red "不受支持的系统"
    red "====================="
    exit
    fi
    if  [ -n "$(grep ' 12\.' /etc/os-release)" ] ;then
    red "====================="
    red "不受支持的系统"
    red "====================="
    exit
    fi
    green "=============================================="
    green "         系统支持检测：支持当前系统"
    green "=============================================="
    green
    green "安装nginx编译需要的软件"
    $systemPackage update >/dev/null 2>&1
    $systemPackage install -y vim vnstat htop wget curl unzip build-essential libpcre3 libpcre3-dev zlib1g-dev liblua5.1-dev libluajit-5.1-dev libgeoip-dev google-perftools libgoogle-perftools-dev >/dev/null 2>&1
elif [ "$release" == "debian" ]; then
    $systemPackage update >/dev/null 2>&1
    green "安装nginx编译需要的软件"
    $systemPackage install -y vim vnstat htop wget curl unzip build-essential libpcre3 libpcre3-dev zlib1g-dev liblua5.1-dev libluajit-5.1-dev libgeoip-dev google-perftools libgoogle-perftools-dev >/dev/null 2>&1
fi
}

function check_env(){
green
if [ -f "/etc/selinux/config" ]; then
    CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$CHECK" != "SELINUX=disabled" ]; then
        green "=============================================="
        green "检测到SELinux开启状态，添加开放80/443端口规则"
        green "=============================================="
        yum install -y policycoreutils-python >/dev/null 2>&1
        semanage port -m -t http_port_t -p tcp 80
        semanage port -m -t http_port_t -p tcp 443
    fi
fi

systemctl status ufw &>/dev/null
if [ "$?" -eq "0" ]; then
  ufw_status=`systemctl status ufw | grep "Active: active"`
  if [ -n "$ufw_status" ]; then
      ufw allow 80/tcp >/dev/null 2>&1
      ufw allow 443/tcp >/dev/null 2>&1
      green
      green "=============================================="
      green "检测到ufw防火墙开启，添加放行80/443端口规则"
      green "=============================================="
      green
  fi
fi

firewall-cmd --state &>/dev/null 2>&1
if [ "$?" -eq "0" ]; then
  firewall_status=`firewall-cmd --state`
  if [ "$firewall_status" == "running" ]; then
    green "检测到firewalld开启，添加放行80/443端口规则"
    firewall-cmd --zone=public --add-port=80/tcp --permanent >/dev/null 2>&1
    firewall-cmd --zone=public --add-port=443/tcp --permanent >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
  fi
fi
$systemPackage -y install net-tools socat >/dev/null 2>&1
Port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
Port443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`
if [ -n "$Port80" ]; then
    process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
    red "==================================================================="
    red "     检测到80端口被占用，占用进程：${process80}，请先卸载"
    red "==================================================================="
    exit 1
fi
if [ -n "$Port443" ]; then
    process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
    red "====================================================================="
    red "     检测到443端口被占用，占用进程：${process443}，请先卸载"
    red "====================================================================="
    exit 1
fi
}

function install(){
    green "=============================================="
    yellow " 请把要绑定的域名解析到VPS的IP，并关闭CDN！"
    yellow " 再在下方输入这个域名，一定不能出错！！！"
    green "=============================================="
	read -p "要绑定的域名（例如 v2ray.com): " your_domain
    short_domain=`echo ${your_domain} | awk -F '.' '{print $(NF-1) "." $NF}'`
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`

    if [ $real_addr == $local_addr ] ; then
    green "=============================================="
	green "         域名解析正常，开始安装nginx"
    green "=============================================="
        install_nginx
    else
    red "========================================"
	red "  域名解析地址与本VPS的IP地址不一致"
	red "  若确认解析成功,可强制脚本继续运行"
	red "======================================="
	read -p "是否强制运行 ?请输入 [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
      green "强制继续运行脚本"
	    sleep 1s
	    install_nginx
	else
	    exit 1
	fi
fi
}

#安装nginx
function install_nginx(){
    wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1a.tar.gz >/dev/null 2>&1
    tar xzvf openssl-1.1.1a.tar.gz >/dev/null 2>&1
    mkdir /etc/nginx
    mkdir /etc/nginx/ssl
    mkdir /etc/nginx/conf.d
    wget https://nginx.org/download/nginx-1.15.8.tar.gz >/dev/null 2>&1
    tar xf nginx-1.15.8.tar.gz && rm nginx-1.15.8.tar.gz >/dev/null 2>&1
    cd nginx-1.15.8
    ./configure --prefix=/etc/nginx --with-openssl=../openssl-1.1.1a --with-openssl-opt='enable-tls1_3' --with-http_v2_module --with-http_ssl_module --with-http_gzip_static_module --with-http_stub_status_module --with-http_sub_module --with-stream --with-stream_ssl_module  >/dev/null 2>&1
    green
    green "=============================================="
    green "  正在编译安装nginx和组件，可能等待时间较长，"
    green "  通常要5到10分钟，可以去喝一口水或听一首歌？"
    green "=============================================="
    green "………………"
    green
    make >/dev/null 2>&1
    make install >/dev/null 2>&1

cat > /etc/nginx/conf/nginx.conf <<-EOF
user  root;
worker_processes  1;
error_log  /etc/nginx/logs/error.log warn;
pid        /etc/nginx/logs/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/conf/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /etc/nginx/logs/access.log  main;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;
    include /etc/nginx/conf.d/*.conf;

# 不使用v2ray自带的TLS，使用Nginx的TLS
server {
    listen  443 ssl;
    server_name           $your_domain;
    ssl_certificate       /etc/nginx/ssl/fullchain.cer;
    ssl_certificate_key   /etc/nginx/ssl/$your_domain.key;
    ssl_protocols         TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers           HIGH:!aNULL:!MD5;
    location / {
    proxy_pass http://localhost:11234;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    }
}

# 指定nginx的证书路径和网站目录
server {
    listen       443 ssl;
    server_name      $your_domain;
    ssl_certificate       /etc/nginx/ssl/fullchain.cer;
    ssl_certificate_key   /etc/nginx/ssl/$your_domain.key;
    root /etc/nginx/html;
    index index.php index.html index.htm;
}

# 长域名跳到短域名
server {
    listen  443 ssl;
    server_name        www.$short_domain;
    location / {
    proxy_pass http://$short_domain;
    }
}

# 同一个VPS另外一个网站的域名，通过nginx跳转到443端口
server {
  listen       443 ssl;
  server_name      xxxxxxx.com;  #修改为另外一个域名
  ssl_certificate       /etc/nginx/ssl/fullchain.cer;
  ssl_certificate_key   /etc/nginx/ssl/$your_domain.key;
  location / {
  proxy_pass https://$real_addr:44399;  #将其他网站的443端口改为44399
  }
}

# 将解析到此IP的域名、http地址，重定向到对应的https网址上
server {
    listen          80;
    server_name      $your_domain $short_domain xxxxxxx.com;   #修改为另外一个域名
    return 301 https://\$server_name\$request_uri;
    }
}
EOF

curl https://get.acme.sh | sh
~/.acme.sh/acme.sh  --issue  -d $your_domain  --standalone
~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
    --key-file   /etc/nginx/ssl/$your_domain.key \
    --fullchain-file /etc/nginx/ssl/fullchain.cer

newpath=$(cat /dev/urandom | head -1 | md5sum | head -c 4)

cat > /etc/nginx/conf.d/default.conf<<-EOF
server {
    listen       80;
    server_name  $your_domain;
    rewrite ^(.*)$  https://\$host\$1 permanent;
}
server {
    listen 443 ssl http2;
    server_name $your_domain;
    root /etc/nginx/html;
    index index.php index.html;
    ssl_certificate /etc/nginx/ssl/fullchain.cer;
    ssl_certificate_key /etc/nginx/ssl/$your_domain.key;
    #TLS 版本控制
    ssl_protocols   TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers     'TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5';
    ssl_prefer_server_ciphers   on;
    # 开启 1.3 0-RTT
    ssl_early_data  on;
    ssl_stapling on;
    ssl_stapling_verify on;
    #add_header Strict-Transport-Security "max-age=31536000";
    #access_log /var/log/nginx/access.log combined;
    location /$newpath {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:11234;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
cat > /etc/systemd/system/nginx.service<<-EOF
[Unit]
Description=nginx service
After=network.target
[Service]
Type=forking
ExecStart=/etc/nginx/sbin/nginx
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/etc/nginx/sbin/nginx -s quit
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
chmod 777 /etc/systemd/system/nginx.service
systemctl enable nginx.service
ln -s /etc/nginx/sbin/nginx /usr/bin/nginx
install_v2ray
}


#安装v2ray
function install_v2ray(){
    #bash <(curl -L -s https://install.direct/go.sh)
    bash <(curl -L -s https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    cd /usr/local/etc/v2ray/
    rm -f config.json
cat > /usr/local/etc/v2ray/config.json<<-EOF
{
  "log" : {
    "access": "none",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbound": {
    "port": 11234,
    "listen":"127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "myuuid",
          "level": 1,
          "alterId": 64,
          "email": "myemail@gmail.com"
        }
      ]
    },
     "streamSettings": {
      "network": "ws",
      "wsSettings": {
         "path": "/mypath"
        }
     }
  },
  "outbound": {
    "protocol": "freedom",
    "settings": {}
  }
}
EOF
    v2uuid=$(cat /proc/sys/kernel/random/uuid)
    sed -i "s/myuuid/$v2uuid/;" config.json
    sed -i "s/mypath/$newpath/;" config.json
    cd /etc/nginx/html
    rm -f ./* >/dev/null 2>&1
    wget -O /etc/nginx/html/web.zip --no-check-certificate https://templated.co/intensify/download >/dev/null 2>&1
    unzip web.zip >/dev/null 2>&1
    systemctl enable v2ray.service >/dev/null 2>&1
    systemctl restart v2ray.service >/dev/null 2>&1
    systemctl restart nginx.service>/dev/null 2>&1

cat > /usr/local/etc/v2ray/qr_config.json<<-EOF
{"add":"${real_addr}","id":"${v2uuid}","net":"ws","host":"${your_domain}","port":"443","ps":"Vmess_${newpath}","tls":"tls","v":2,"aid":64,"path":"/${newpath}","type":"none"}
EOF

v2ray_link="vmess://$(base64 -w 0 /usr/local/etc/v2ray/qr_config.json)"
rm -f /usr/local/etc/v2ray/qr_config.json

cat > /usr/local/etc/v2ray/myconfig.json<<-EOF

=============账 号 信 息===============
地址：${real_addr}
端口：443
uuid：${v2uuid}
额外id：64
加密方式：aes-128-gcm
传输协议：ws
别名：Vmess_${newpath}
路径：${newpath}
底层传输：tls

Qv2ray二维码链接：${v2ray_link}

v2rayN二维码链接：${v2ray_link}

* 两种链接相同

nginx配置：/etc/nginx/conf/nginx.conf
v2ray配置：/usr/local/etc/v2ray/config.json

EOF

green "==============================="
green "  安装已经完成，账号信息如下"
green "==============================="
green
green "地址：${real_addr}"
green "端口：443"
green "uuid：${v2uuid}"
green "额外id：64"
green "加密方式：aes-128-gcm"
green "传输协议：ws"
green "别名：Vmess_${newpath}"
green "路径：${newpath}"
green "底层传输：tls"
green
green "Qv2ray二维码链接：${v2ray_link}"
green
green "V2rayN二维码链接：${v2ray_link}"
green
green "* 两种链接相同"
green
green "Nginx配置：/etc/nginx/conf/nginx.conf"
green "V2ray配置：/usr/local/etc/v2ray/config.json"
green
}

function web_download () {
  rm -rf /etc/nginx/html
  mkdir /etc/nginx/html
  cd /etc/nginx/html
  green "请选择下面任意一个伪装网站模板，安装之前可以查看网站demo:"
  green "1. https://templated.co/intensify(素雅模板)"
  green "2. https://templated.co/binary(人物照片)"
  green "3. https://templated.co/retrospect(风景照片)"
  green "4. https://templated.co/spatial(山林照片)"
  green "5. https://templated.co/monochromed(灰色城市)"
  green "6. https://templated.co/transit(博客留言)"
  green "7. https://templated.co/interphase(靓丽城市)"
  green "8. https://templated.co/ion(大山照片)"
  green "9. https://templated.co/solarize(绿荫照片)"
  green "10. https://templated.co/phaseshift(绿荫照片)"
  green "11. https://templated.co/horizons(红果照片)"
  green "12. https://templated.co/grassygrass(绿草照片)"
  green "13. https://templated.co/breadth(指南针照片)"
  green "14. https://templated.co/undeviating(高楼蓝天)"
  green "15. https://templated.co/lorikeet(绿色鹦鹉)"
  read -p "请输入要下载的网站数字编号:" siteNum
  case $siteNum in
    1)
      wget -O web.zip --no-check-certificate https://templated.co/intensify/download >/dev/null 2>&1
    ;;
    2)
      wget -O web.zip --no-check-certificate https://templated.co/binary/download >/dev/null 2>&1
    ;;
    3)
      wget -O web.zip --no-check-certificate https://templated.co/retrospect/download >/dev/null 2>&1
    ;;
    4)
      wget -O web.zip --no-check-certificate https://templated.co/spatial/download >/dev/null 2>&1
    ;;
    5)
      wget -O web.zip --no-check-certificate https://templated.co/monochromed/download >/dev/null 2>&1
    ;;
    6)
      wget -O web.zip --no-check-certificate https://templated.co/transit/download >/dev/null 2>&1
    ;;
    7)
      wget -O web.zip --no-check-certificate https://templated.co/interphase/download >/dev/null 2>&1
    ;;
    8)
      wget -O web.zip --no-check-certificate https://templated.co/ion/download >/dev/null 2>&1
    ;;
    9)
      wget -O web.zip --no-check-certificate https://templated.co/solarize/download >/dev/null 2>&1
    ;;
    10)
      wget -O web.zip --no-check-certificate https://templated.co/phaseshift/download >/dev/null 2>&1
      ;;
    11)
      wget -O web.zip --no-check-certificate https://templated.co/horizons/download >/dev/null 2>&1
    ;;
    12)
      wget -O web.zip --no-check-certificate https://templated.co/grassygrass/download >/dev/null 2>&1
    ;;
    13)
      wget -O web.zip --no-check-certificate https://templated.co/breadth/download >/dev/null 2>&1
    ;;
    14)
      wget -O web.zip --no-check-certificate https://templated.co/undeviating/download >/dev/null 2>&1
    ;;
    15)
      wget -O web.zip --no-check-certificate https://templated.co/lorikeet/download >/dev/null 2>&1
    ;;
    *)
      wget -O web.zip --no-check-certificate https://templated.co/intensify/download >/dev/null 2>&1
    ;;
    esac
    unzip web.zip >/dev/null 2>&1
    green "网站已切换，请在浏览器查看。"
    sleep 5
}


function change_bbr() {
  wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"
  chmod +x tcp.sh
  ./tcp.sh
  green "5秒后返回"
  sleep 5
}

function install_bbr() {
	local test1=$(sed -n '/net.ipv4.tcp_congestion_control/p' /etc/sysctl.conf)
	local test2=$(sed -n '/net.core.default_qdisc/p' /etc/sysctl.conf)
	if [[ $(uname -r | cut -b 1) -eq 4 ]]; then
		case $(uname -r | cut -b 3-4) in
		9. | [1-9][0-9])
			if [[ $test1 == "net.ipv4.tcp_congestion_control = bbr" && $test2 == "net.core.default_qdisc = fq" ]]; then
				local is_bbr=true
			else
				local try_enable_bbr=true
			fi
			;;
		esac
	fi
	if [[ $is_bbr ]]; then
		echo
		green "BBR 加速已启用，无需再安装"
		echo
    elif [[ $try_enable_bbr ]]; then
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
		echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
		sysctl -p >/dev/null 2>&1
		echo
		green "BBR 加速已成功启用，更换BBR请选 4"
		echo
	else
		# https://teddysun.com/489.html
		bash <(curl -s -L https://github.com/teddysun/across/raw/master/bbr.sh)
	fi
}

function update_v2ray() {
    bash <(curl -L -s https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    systemctl restart v2ray
    green "V2ray已更新"
    sleep 5
}

function remove_v2ray_nginx() {
	read -p "卸载后脚本安装的程序将全部清除，确定需要卸载? 请输入 [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
    systemctl stop v2ray.service
    systemctl disable v2ray.service
    systemctl stop nginx.service
    systemctl disable nginx.service

    rm -rf /usr/local/bin/v2ray /usr/local/bin/v2ctl >/dev/null 2>&1
    rm -rf /usr/local/share/v2ray/ /usr/local/etc/v2ray/ >/dev/null 2>&1
    rm -rf /etc/systemd/system/v2ray* >/dev/null 2>&1
    rm -rf /etc/nginx >/dev/null 2>&1

    green "卸载完成，系统已还原"
    sleep 5
	else
	    exit 1
	fi
}

function start_menu(){
    clear
    green " ========================================================="
    green " 介绍: 一键安装 V2ray+ws+tls+CDN，支持cf自选节点"
    green " 支持: Centos7/Debian9+/Ubuntu16.04+"
    green " 作者: CookedMeat2"
    green " 时间: 2020-10-19"
    green " ========================================================="
    green "  1. 安装 V2ray+ws+tls"
    green
    green "  2. 更新 V2ray主程序"
    green
    green "  3. 更换 伪装网站"
    green
    green "  4. 更换 BBR加速"
    green " --------------------------------------------------------"
    green "  5. 编辑 V2ray配置"
    green
    green "  6. 编辑 Nginx配置"
    green
    green "  7. 查看 账号信息"
    green " --------------------------------------------------------"
    green "  8. 重启 V2ray+Nginx"
    green
    green "  9. 停止 V2ray+Nginx"
    green
    green " 10. 卸载 V2ray+Nginx"
    green
    green " 11. 退出脚本"
    green
    read -p "请输入一个数字后回车:" num
    case "$num" in
    1)
    check_os
    check_env
    install
    install_bbr
    ;;
    2)
    update_v2ray
    start_menu
    ;;
    3)
    web_download
    start_menu
    ;;
    4)
    change_bbr
    start_menu
    ;;
    5)
    vim /usr/local/etc/v2ray/config.json
    systemctl restart v2ray.service
    ;;
    6)
    vim /etc/nginx/conf/nginx.conf
    systemctl restart nginx.service
    ;;
    7)
    cat /usr/local/etc/v2ray/myconfig.json
    ;;
    8)
    systemctl restart v2ray.service
    systemctl restart nginx.service
    green "v2ray+nginx服务已重启！"
    sleep 5
    start_menu
    ;;
    9)
    systemctl stop v2ray.service
    systemctl stop nginx.service
    green "v2ray+nginx服务已停止！"
    sleep 5
    start_menu
    ;;
    10)
    remove_v2ray_nginx
    start_menu
    ;;
    11)
    exit 1
    ;;
    *)
    clear
    red "请输入正确的数字！"
    sleep 5
    start_menu
    ;;
    esac
}

start_menu
