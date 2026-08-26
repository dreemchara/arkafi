#!/bin/bash

MY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Поднимаемся на уровень выше и подключаем конфиг
if [ -f "${MY_DIR}/../config/firewall.conf" ]; then
    source "${MY_DIR}/../config/firewall.conf"
else
    echo "Ошибка: Конфиг не найден"
    exit 1
fi

# Переменные
WAN=$WAN_INTERFACE
LAN1=$LAN_INTERFACE
LAN1_IP_RANGE=$LAN_IP_RANGE
PROXY_PORT=$PROXY_PORT
PROXY_IP=$PROXY_IP
PROXY_USER=$PROXY_USER
SSH_PORT=$SSH_PORT


# Очищаем правила
iptables -F
iptables -F -t nat
iptables -F -t mangle
iptables -X
iptables -t nat -X
iptables -t mangle -X

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.$LAN1.rp_filter=0
sysctl -w net.ipv4.conf.lo.rp_filter=0

ipset create -! allowed_macs hash:mac

ipset create -! runetlist hash:net
ipset add runetlist 77.88.8.8
ipset add runetlist 77.88.8.1

# Очищаем маршрут пакетов
ip rule del fwmark 1 lookup 100 2>/dev/null
# Добавляем пустой маршрут и тут же очищаем таблицу
ip route add throw local table 100 2>/dev/null
ip route flush table 100

#Cоздаём маршрут пакетов для TPROXY
ip rule add fwmark 1 lookup 100 priority 100
ip route add local 0.0.0.0/0 dev lo table 100

# Основная политика
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT


# Разрешаем localhost и локалку
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i $LAN1 -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -o $LAN1 -j ACCEPT

# открываем доступ к SSH, nginx, DHCP, DNS, capture portal, docker
iptables -A INPUT -i $WAN -p tcp --dport $SSH_PORT -j ACCEPT

iptables -A INPUT -i $LAN1 -p tcp --dport $PORTAL_PORT -j ACCEPT
iptables -A INPUT -i $LAN1 -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i $LAN1 -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i $LAN1 -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -i $LAN1 -p udp --dport 67 -j ACCEPT 


# редирект на сайт регистрации незагеранных пользователей 
iptables -t nat -I PREROUTING \
    -i $LAN1 \
    -p tcp --dport 80 \
    -m set ! --match-set allowed_macs src \
    -j REDIRECT --to-ports $PORTAL_PORT


# Рзрешаем пинги
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Разрешаем все исходящие подключения сервера
iptables -A OUTPUT -o $WAN -j ACCEPT
# Разрешаем все входящие подключения сервера
#iptables -A INPUT -i $WAN -j ACCEPT

# разрешаем установленные подключения
iptables -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p all -m state --state ESTABLISHED,RELATED -j ACCEPT

# Отбрасываем неопознанные пакеты
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
# Отбрасываем нулевые пакеты
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# Закрываемся от syn-flood атак
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A OUTPUT -p tcp ! --syn -m state --state NEW -j DROP

# Разрешаем доступ из локалки наружу тем кто есть в allowed_macs
iptables -A FORWARD -i $LAN1 -m set --match-set allowed_macs src -j ACCEPT
# Закрываем доступ снаружи в локалку
iptables -A FORWARD -i $WAN -o $LAN1 -j REJECT


iptables -t mangle -A OUTPUT -m owner --uid-owner $PROXY_USER -j MARK --set-mark 0x2

# --- Цепочка HYSTERIA ---
iptables -t mangle -N HYSTERIA

# я не ебу нахуя это
iptables -t mangle -A HYSTERIA -p tcp -m socket --transparent -j MARK --set-mark 1
iptables -t mangle -A HYSTERIA -p udp -m socket --transparent -j MARK --set-mark 1
iptables -t mangle -A HYSTERIA -m socket -j RETURN

# Исключаем локальные сети
iptables -t mangle -A HYSTERIA -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A HYSTERIA -d 100.64.0.0/10 -j RETURN
iptables -t mangle -A HYSTERIA -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A HYSTERIA -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A HYSTERIA -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A HYSTERIA -d 192.0.0.0/24 -j RETURN
iptables -t mangle -A HYSTERIA -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A HYSTERIA -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A HYSTERIA -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A HYSTERIA -d 192.168.0.0/16 -p tcp ! --dport 53 -j RETURN
iptables -t mangle -A HYSTERIA -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN

# Перенаправляем пакеты с маркой 1 на 25375 порт
iptables -t mangle -A HYSTERIA -p tcp -j TPROXY --on-port $PROXY_PORT --on-ip $PROXY_IP --tproxy-mark 0x1
iptables -t mangle -A HYSTERIA -p udp -j TPROXY --on-port $PROXY_PORT --on-ip $PROXY_IP --tproxy-mark 0x1



# цепочки для счёта данных

#входящий трафик
iptables -t mangle -N ACCT_PROXY_IN
iptables -t mangle -N ACCT_DIRECT_IN

iptables -t mangle -A PREROUTING -i $LAN1 \
    -m set --match-set allowed_macs src \
    -m set ! --match-set runetlist dst \
    -j ACCT_PROXY_IN
 
iptables -t mangle -A PREROUTING -i $LAN1 \
    -m set --match-set allowed_macs src \
    -m set  --match-set runetlist dst \
    -j ACCT_DIRECT_IN

#исходящий трафик
iptables -t mangle -N ACCT_PROXY_OUT
iptables -t mangle -N ACCT_DIRECT_OUT

iptables -t mangle -A POSTROUTING -o $LAN1 \
    -d $LAN1_IP_RANGE \
    -m mark --mark 0x2 \
    -j ACCT_PROXY_OUT

iptables -t mangle -A POSTROUTING -o $LAN1 \
    -d $LAN1_IP_RANGE \
    -m mark ! --mark 0x2 \
    -j ACCT_DIRECT_OUT


# Посылаем $LAN1 в HYSTERIA тех кто есть в allowed_macs если идёт не в runetlist
iptables -t mangle -A PREROUTING -i $LAN1 -m set --match-set allowed_macs src -m set ! --match-set runetlist dst -j HYSTERIA

# Маскарадим
iptables -t nat -A POSTROUTING -s $LAN1_IP_RANGE -o $WAN -j MASQUERADE