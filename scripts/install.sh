#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Пожалуйста, запустите скрипт от sudo."
  exit 1
fi


MY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Подключаем конфиг
if [ -f "${MY_DIR}/firewall/config/firewall.conf" ]; then
    source "${MY_DIR}/firewall/config/firewall.conf"
else
    echo "Ошибка: Конфиг не найден"
    exit 1
fi

INSTALL_DIR=$INSTALL_DIR

echo "Установка системных зависимостей..."
apt-get update
apt-get install -y python3 python3-venv python3-pip postgresql postgresql-contrib ipset iptables rsync acl

# Перемещаем
mkdir -p "$INSTALL_DIR"
rsync -av --exclude='install.sh' "$MY_DIR/" "$INSTALL_DIR/"


echo "Создание Python venv..."
python3 -m venv ${INSTALL_DIR}/venv
${INSTALL_DIR}/venv/bin/pip install -r ${INSTALL_DIR}/portal/requirements.txt


chown -R www-data:www-data ${INSTALL_DIR}/portal
chmod 640 ${INSTALL_DIR}/firewall/config/firewall.conf
setfacl -m u:www-data:r ${INSTALL_DIR}/firewall/config/firewall.conf


echo "Создание systemd сервисов..."
#-----SYSTEMD
# arkafi-portal.service
cat > /etc/systemd/system/arkafi-portal.service <<EOF
[Unit]
Description=Arkafi captive portal
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${INSTALL_DIR}/portal

ExecStart=${INSTALL_DIR}/venv/bin/gunicorn -w 4 -b 0.0.0.0:${PORTAL_PORT} app:app

[Install]
WantedBy=multi-user.target
EOF

# arkafi-iptables.service
cat > /etc/systemd/system/arkafi-iptables.service <<EOF
[Unit]
Description=Arkafi IPTables Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash ${INSTALL_DIR}/firewall/rules/iptables.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# firewall-sync.service
cat > /etc/systemd/system/arkafi-firewall-sync.service <<EOF
[Unit]
Description=Arkafi service for firewall sync

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/firewall/sync/firewall_updater.py

[Install]
WantedBy=multi-user.target
EOF

# firewall-sync.service timer
cat > /etc/systemd/system/arkafi-firewall-sync.timer <<EOF
[Unit]
Description=Arkafi timer for arkafi-firewall-sync.service

[Timer]
Unit=arkafi-firewall-sync.service
OnCalendar=*-*-* *:*:00

[Install]
WantedBy=timers.target
EOF


# arkafi-runetlist-updater.service
cat > /etc/systemd/system/arkafi-runetlist-updater.service <<EOF
[Unit]
Description=Arkafi service for update runetlist

[Service]
Type=oneshot
ExecStart=/bin/bash ${INSTALL_DIR}/firewall/rules/runetlist-updater.sh

[Install]
WantedBy=multi-user.target
EOF

# arkafi-runetlist-updater.service timer
cat > /etc/systemd/system/arkafi-runetlist-updater.timer <<EOF
[Unit]
Description=Arkafi timer for arkafi-runetlist-updater.service

[Timer]
Unit=arkafi-runetlist-updater.service
OnCalendar=daily

[Install]
WantedBy=timers.target
EOF

# arkafi-traffic-collector.service
cat > /etc/systemd/system/arkafi-traffic-collector.service<<EOF
[Unit]
Description=Arkafi service for traffic-collector

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/firewall/sync/traffic_collector.py

[Install]
WantedBy=multi-user.target
EOF

# arkafi-traffic-collector.service timer
cat > /etc/systemd/system/arkafi-traffic-collector.timer <<EOF
[Unit]
Description=Arkafi timer for arkafi-traffic-collector.service

[Timer]
Unit=arkafi-traffic-collector.service
OnCalendar=*-*-* *:*:00

[Install]
WantedBy=timers.target
EOF

echo "Запуск сервисов..."
systemctl daemon-reload

systemctl enable arkafi-iptables.service
systemctl enable arkafi-portal.service
systemctl enable arkafi-firewall-sync.timer
systemctl enable arkafi-runetlist-updater.timer
systemctl enable arkafi-traffic-collector.timer

systemctl start arkafi-iptables.service
systemctl start arkafi-portal.service
systemctl start arkafi-firewall-sync.timer
systemctl start arkafi-runetlist-updater.timer
systemctl start arkafi-traffic-collector.timer


#------POSTGRESQL

# Создание БД и пользователя
runuser -u postgres -- psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
runuser -u postgres -- psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

cp ${INSTALL_DIR}/database/init-db.sql /tmp/init-db.sql
runuser -u postgres -- psql -d "$DB_NAME" -f /tmp/init-db.sql
rm /tmp/init-db.sql