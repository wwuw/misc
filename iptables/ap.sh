#!/bin/sh
#=============================================================================================
#内网设备：eth0   外网设备：eth1 拨号后ppp设备：ppp0
#=============================================================================================
#设置防火墙规则
#squid进程启动后,监听客户端http请求的端口是3128,而客户发起的http请求的端口是80,因此,需要利用
#端口生定向将所有对80端口的请求,重定向到3128端口。如不考虑安全，对于squid代理服务器，只需要远行以下
#两条规则即可。
#=============下面在/etc/rc.d/init.d/目录中写代理的防火墙脚本squid_proxy_firewall==============
#define variables
#======================= INPUT VARIABLES =========================================
IPT="/sbin/iptables"
WAN="eth0"
WAN_MODE="PPPOE" #DHCP, STATIC"
WAN_IP=""
LOCAL="wlan0"
LOCAL_DHCP="yes"
LOCAL_IP="192.168.0.1"
ENABLE="1"
DISABLE="0"
#======================= COMMON CONFIG =========================================
WAN_IF="eth0" 
LOCAL_IF="wlan0"
MASHINE=$LOCAL_IP
LOCAL=$MASHINE
DHCP_IP_RANGE="192.168.0.20-192.168.0.250"
DHCP_IP_DNS=$MASHINE
DHCP_IP_GATEWAY=$MASHINE
#======================= SERVER CONFIG =========================================
#web server
WEB_SERVER_SERVICE=$ENABLE
WEB_SERVER_IP=$MASHINE
WEB_SERVER_PORT="80"
WEB_SERVER_PORT_PUBLIC="80"
#web proxy
WEB_PROXY_SERVICE=$ENABLE
WEB_PROXY_IP=$WEB_SERVER_IP
WEB_PROXY_PORT="3128"
#mail server
MAIL_SERVER_ENABLE=$DISABLE
MAIL_SERVER_SERVICE=$DISABLE
MAIL_PROXY_SERVICE=$DISABLE
#ftp server
FTP_SERVER_ENABLE=$DISABLE
FTP_SERVER_SERVICE=$DISABLE
FTP_PROXY_SERVICE=$DISABLE
#SSL SERVER
SSL_SERVER_PORT="443"
#ssh port
SSH_SERVER_PORT="22"

#======================= NETWORK ARCH CONFIG ===================================
# 1 ) SERIES CONNECTED OR PARALLEL CONNECTED FORWARD
# 2 ) PPP DIAL OR FIXED IP TO WAN MODE 
# 3 ) SIGLE OR MULTI-WAN PORT

#======================= SYSTEM PARAMETERS SETUP ===============================
echo $ENABLE > /proc/sys/net/ipv4/ip_forward
#echo $ENABLE > /proc/sys/net/ipv4/ip_dynaddr
#关闭 Explicit Congestion Notification
#echo $DISABLE > /proc/sys/net/ipv4/tcp_ecn
#echo $ENABLE > /proc/sys/net/ipv4/tcp_syncookies
#echo $ENABLE > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

#允许ping开关（“1”禁止ping,“0”允许ping）
#echo $ENABLE > /proc/sys/net/ipv4/icmp_echo_ignore_all
#sysctl -w net.ipv4.icmp_echo_ignore_all=1

#======================= IPTABLES RULES ========================================
#清除链的规则
$IPT -F
$IPT -t nat -F

#清除封包计数器
$IPT -Z
$IPT -t nat -Z

#设置默认策略
$IPT -P INPUT DROP
$IPT -P FORWARD DROP #更严格的用户行为控制方式
$IPT -P OUTPUT DROP

#对本机对外发起的链接的端口范围做出限制，这个端口范围是Debian系统内部做出的设定
#$IPT -A OUTPUT -o $WAN_IF -p tcp --sport 32768:61000 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPT -A INPUT -i $WAN_IF -p tcp --dport 32768:61000 -m state --state ESTABLISHED -j ACCEPT

#无效的报文，防范公网的攻击
#$IPT -A INPUT   -m state --state INVALID -j DROP
#$IPT -A OUTPUT  -m state --state INVALID -j DROP
#$IPT -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP  
#$IPT -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP

#无效的网段
#$IPT -A INPUT -s 10.0.0.0/8       -j DROP 
#$IPT -A INPUT -s 192.0.0.1/24     -j DROP  
#$IPT -A INPUT -s 169.254.0.0/16   -j DROP 
#$IPT -A INPUT -s 172.16.0.0/12    -j DROP  
#$IPT -A INPUT -s 224.0.0.0/4      -j DROP  
#$IPT -A INPUT -d 224.0.0.0/4      -j DROP  
#$IPT -A INPUT -s 240.0.0.0/5      -j DROP 
#$IPT -A INPUT -d 240.0.0.0/5      -j DROP 
#$IPT -A INPUT -s 0.0.0.0/8        -j DROP 
#$IPT -A INPUT -d 0.0.0.0/8        -j DROP  
#$IPT -A INPUT -d 239.255.255.0/24 -j DROP 
#$IPT -A INPUT -d 255.255.255.255  -j DROP

#======================= local loopback ========================================
#允许本地连接
$IPT -A INPUT -i lo  -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

#======================= SSH server ============================================
#允许内网和外网用户发起SSH链接（包括SCP）
$IPT -A INPUT -p tcp --dport $SSH_SERVER_PORT -i $LOCAL_IF -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport $SSH_SERVER_PORT -o $LOCAL_IF -m state --state ESTABLISHED -j ACCEPT

#======================= PING unit =============================================
#内网，外网和本地均可以ping本机
$IPT -A OUTPUT -p icmp -j ACCEPT
$IPT -A INPUT -p icmp -j ACCEPT
#内网ping外网
$IPT -A FORWARD -p icmp -i $LOCAL_IF -o $WAN_IF   -m iprange --src-range $DHCP_IP_RANGE -m state --state NEW -j ACCEPT
$IPT -A FORWARD -p icmp -o $LOCAL_IF -i $WAN_IF -m state --state ESTABLISHED -j ACCEPT

#======================= NAT for access INTERNET ===============================
$IPT -t nat -A POSTROUTING -s 192.168.0.0/24 -o $WAN_IF -j MASQUERADE 

#======================= DNS service unit ======================================
#允许本机向外的dns查询
$IPT -A OUTPUT -p udp --dport 53 -o $WAN_IF -m state --state NEW -j ACCEPT
$IPT -A INPUT -p udp --sport 53 -i $WAN_IF -m state --state ESTABLISHED -j ACCEPT
#允许内网机器向本机发起的DNS查询
$IPT -A INPUT -p udp --dport 53 -i $LOCAL_IF -m iprange --src-range $DHCP_IP_RANGE -m state --state NEW -j ACCEPT
$IPT -A OUTPUT -p udp --sport 53 -o $LOCAL_IF -m iprange --dst-range $DHCP_IP_RANGE -m state --state ESTABLISHED -j ACCEPT
#允许内网使用自己指定的DNS server ！潜在的风险是本地web server解析会出现问题，使用
#地址重定向解决，类似proxy做法。
#$IPT -A FORWARD -p udp --dport 53 -o $WAN_IF -m state --state NEW -j ACCEPT
#$IPT -A FORWARD -p udp --sport 53 -i $WAN_IF -m state --state ESTABLISHED -j ACCEPT
#all DNS request MUST redirect to local dnsmasq service now.
$IPT -t nat -A PREROUTING -p udp --dport 53 -i $LOCAL_IF -m iprange --src-range $DHCP_IP_RANGE -j REDIRECT --to-ports 53
#======================= DHCP service unit =====================================
$IPT -A OUTPUT -p udp --dport 68 -o $LOCAL_IF -j ACCEPT
$IPT -A INPUT -p udp --dport 67 -i $LOCAL_IF  -j ACCEPT

#======================= HTTP server unit ======================================
#允许对本机的WEB server发起的服务请求
$IPT -A INPUT -p tcp --dport $WEB_PROXY_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport $WEB_PROXY_PORT -m state --state ESTABLISHED -j ACCEPT
#允许本地对本机的WEB server发起SSL服务请求，可以用于工程管理服务，或者用户操控界面
$IPT -A INPUT -p tcp --dport $SSL_SERVER_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport $SSL_SERVER_PORT -m state --state ESTABLISHED -j ACCEPT

#======================= HTTP proxy unit =======================================
#允许HTTP proxy进程向外发起对80端口代理的请求
$IPT -A OUTPUT -p tcp --dport $WEB_SERVER_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --sport $WEB_SERVER_PORT -m state --state ESTABLISHED -j ACCEPT
#允许HTTP server和proxy发起对外的SSL链接请求
$IPT -A OUTPUT -p tcp --dport $SSL_SERVER_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --sport $SSL_SERVER_PORT -m state --state ESTABLISHED -j ACCEPT
#内网的WEB访问（80端口）重定向到本机的HTTP proxy
#$IPT -t nat -A PREROUTING -p tcp --dport $WEB_SERVER_PORT -i $LOCAL_IF -d $MASHINE -m iprange --src-range $DHCP_IP_RANGE -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -t nat -A PREROUTING -p tcp --dport $WEB_SERVER_PORT -i $LOCAL_IF -m iprange --src-range $DHCP_IP_RANGE -m state --state NEW,ESTABLISHED -j REDIRECT --to-ports $WEB_PROXY_PORT

#======================= SSL forwards unit =====================================
#enable local PC to use SSL connection
$IPT -A FORWARD -p tcp --dport $SSL_SERVER_PORT -o $WAN_IF -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A FORWARD -p tcp --sport $SSL_SERVER_PORT -i $WAN_IF -m state --state ESTABLISHED -j ACCEPT

#======================= NTP service unit ======================================
#ntpdate need update to remote server
#ntpd nee to provide time service to subnet user


#======================= MAIL service unit =====================================

#======================= FTP service unit ======================================

#======================= p2p,xunlei,QQ, etc., block ============================

#======================= local user's behaviours management ====================
#本地管理者使用的特殊ip地址192.168.1.6-192.168.1.10共5个本地特殊地址，使用mac和ip
#捆绑的方式操作。
#======================= home server virtul ====================================
#$IPT -t nat -A PREROUTING -p tcp --dport $WEB_SERVER_PORT -i $WAN_IF -j DNAT --to 192.168.1.240
#$IPT -t nat -A PREROUTING -p tcp --dport $SSL_SERVER_PORT -i $WAN_IF -j DNAT --to 192.168.1.240
#$IPT -t nat -A PREROUTING -p tcp --dport 4125 -i $WAN_IF -j DNAT --to 192.168.1.240
#$IPT -A FORWARD -p tcp -d 192.168.1.240 -i $WAN_IF --dport $WEB_SERVER_PORT -j ACCEPT
#$IPT -A FORWARD -p tcp -s 192.168.1.240 -o $WAN_IF --sport $WEB_SERVER_PORT -j ACCEPT
#$IPT -A FORWARD -p tcp -d 192.168.1.240 -i $WAN_IF --dport $SSL_SERVER_PORT -j ACCEPT
#$IPT -A FORWARD -p tcp -s 192.168.1.240 -o $WAN_IF --sport $SSL_SERVER_PORT -j ACCEPT
#$IPT -A FORWARD -p tcp -d 192.168.1.240 -i $WAN_IF --dport 4125 -j ACCEPT
#$IPT -A FORWARD -p tcp -s 192.168.1.240 -o $WAN_IF --sport 4125 -j ACCEPT



# 11) log
#$IPT -N LOGGING                                                	    # Create `LOGGING` chain for logging denied packets 
#$IPT -A INPUT -j LOGGING                                            # Create `LOGGING` chain for logging denied packets   
#$IPT -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables Packet Dropped: " --log-level 6    # Log denied packets to /var/log/messages 
#$IPT -A LOGGING -j DROP                                            	# Drop everything 

#当然了，来点日志记录会对网管员有所帮助。
#$IPT -A INPUT -i eth+ -p tcp --dport 80 -j LOG --log-prefix "iptables_80_alert" --log-level info
#$IPT -A INPUT -i eth+ -p tcp --dport 21 -j LOG --log-prefix "iptables_21_alert" --log-level info
#$IPT -A INPUT -i eth+ -p tcp --dport 22 -j LOG --log-prefix "iptables_22_alert" --log-level info
#$IPT -A INPUT -i eth+ -p tcp --dport 25 -j LOG --log-prefix "iptables_25_alert" --log-level info
#$IPT -A INPUT -i eth+ -p icmp --icmp-type 8 -j LOG --log-prefix "iptables_icmp8_alert" --log-level info




