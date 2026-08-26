import subprocess
import re
import psycopg2
from collections import defaultdict
from datetime import datetime, timezone

db_config = {
    "dbname": "arkafi",
    "user": "arkafi",
    "password": "44m17k8@qweasd",
    "host": "localhost",
    "port": "5432"
    }


def read_and_reset_chain(table: str, chain: str) -> dict[str, int]:
    """
    Читает счётчики байт по MAC из цепи iptables и сбрасывает их.
    """
    # Получаем вывод
    try:
        out = subprocess.check_output(
            ["/usr/sbin/iptables", "-t", table, "-nvxL", chain],
            text=True,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print(f"Ошибка выполнения iptables: {e.output}")
        return {}

    result = {}
    
    # Парсим строки
    for line in out.splitlines():
        # Ищем MAC-адрес (XX:XX:XX:XX:XX:XX)
        mac_match = re.search(r'([0-9a-fA-F:]{17})', line)
        if not mac_match:
            continue
            
        # Извлекаем колонку байт
        parts = line.split()
        if len(parts) >= 2:
            try:
                bytes_count = int(parts[1])
                mac_address = mac_match.group(1).lower()
                result[mac_address] = bytes_count
            except ValueError:
                continue

    # Сбрасываем счётчики 
    if result:
        subprocess.run(["/usr/sbin/iptables", "-t", table, "-Z", chain], check=True)

    return result

def read_dnsmasq_leases(leases_file="/var/lib/misc/dnsmasq.leases") -> dict[str, str]:
    """
    Читает файл аренд dnsmasq.
    Возвращает {ip: mac}.
    """
    ip_to_mac = {}
    try:
        with open(leases_file) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    mac = parts[1].lower()
                    ip  = parts[2]
                    ip_to_mac[ip] = mac
    except FileNotFoundError:
        print(f"[ERROR] Файл аренд не найден: {leases_file}")
    return ip_to_mac

def read_and_reset_chain_by_ip(table: str, chain: str) -> dict[str, int]:
    """
    Читает счётчики байт по IP из цепи iptables и сбрасывает их.
    Возвращает {ip: bytes}.
    """
    try:
        out = subprocess.check_output(
            ["/usr/sbin/iptables", "-t", table, "-nvxL", chain],
            text=True,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print(f"Ошибка выполнения /usr/sbin/iptables: {e.output}")
        return {}

    result = {}
    for line in out.splitlines():
        # В POSTROUTING dst — 8-я колонка (0-based: pkts bytes target prot opt in out dst)
        parts = line.split()
        if len(parts) < 9:
            continue
        try:
            bytes_count = int(parts[1])
            dst = parts[8]  # колонка destination
            # Пропускаем служебные строки (0.0.0.0/0, заголовки и т.д.)
            if '/' in dst or not re.match(r'^\d+\.\d+\.\d+\.\d+$', dst):
                continue
            if bytes_count > 0:
                result[dst] = bytes_count
        except (ValueError, IndexError):
            continue

    if result:
        subprocess.run(["/usr/sbin/iptables", "-t", table, "-Z", chain], check=True)

    return result


def collect():
    ts = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    proxy_counts_in = read_and_reset_chain("mangle", "ACCT_PROXY_IN")
    direct_counts_in = read_and_reset_chain("mangle", "ACCT_DIRECT_IN")
    proxy_counts_out  = read_and_reset_chain_by_ip("mangle", "ACCT_PROXY_OUT")
    direct_counts_out = read_and_reset_chain_by_ip("mangle", "ACCT_DIRECT_OUT")

    all_macs = set(proxy_counts_in) | set(direct_counts_in)
    all_ips  = set(proxy_counts_out) | set(direct_counts_out)


    print(f"[DEBUG] proxy_out:  {proxy_counts_out}")
    print(f"[DEBUG] direct_out: {direct_counts_out}")



    if not all_macs and not all_ips:
        return

    # Читаем аренды dnsmasq — IP → MAC
    ip_to_mac = read_dnsmasq_leases()
    print(f"[DEBUG] dnsmasq leases: {ip_to_mac}")

    # Переводим IP → MAC для исходящего трафика
    # Теперь у нас всё в MAC, один путь резолва
    for ip, b in list(proxy_counts_out.items()):
        mac = ip_to_mac.get(ip)
        if mac:
            proxy_counts_in[mac] = proxy_counts_in.get(mac, 0)   # убеждаемся что ключ есть
            all_macs.add(mac)
        else:
            print(f"[WARN] IP {ip} не найден в dnsmasq leases")

    for ip, b in list(direct_counts_out.items()):
        mac = ip_to_mac.get(ip)
        if mac:
            direct_counts_out_by_mac = direct_counts_out_by_mac if 'direct_counts_out_by_mac' in dir() else {}
            all_macs.add(mac)
        else:
            print(f"[WARN] IP {ip} не найден в dnsmasq leases")

    conn = psycopg2.connect(**db_config)
    try:
        cur = conn.cursor()

        # Один запрос — MAC → user_id для всех
        all_macs_lower = [mac.lower() for mac in all_macs]
        cur.execute(
            "SELECT lower(mac::text), user_id FROM arkafi_users_mac WHERE lower(mac::text) = ANY(%s)",
            (all_macs_lower,)
        )
        mac_to_user = {row[0]: row[1] for row in cur.fetchall()}

        per_user = defaultdict(lambda: [0, 0, 0, 0])  # [proxy_in, direct_in, proxy_out, direct_out]

        for mac, b in proxy_counts_in.items():
            uid = mac_to_user.get(mac.lower())
            if uid:
                per_user[uid][0] += b

        for mac, b in direct_counts_in.items():
            uid = mac_to_user.get(mac.lower())
            if uid:
                per_user[uid][1] += b

        for ip, b in proxy_counts_out.items():
            mac = ip_to_mac.get(ip)
            if not mac:
                continue
            uid = mac_to_user.get(mac.lower())
            if uid:
                per_user[uid][2] += b

        for ip, b in direct_counts_out.items():
            mac = ip_to_mac.get(ip)
            if not mac:
                continue
            uid = mac_to_user.get(mac.lower())
            if uid:
                per_user[uid][3] += b

        for uid, (pb, db, pob, dob) in per_user.items():
            if pb == 0 and db == 0 and pob == 0 and dob == 0:
                continue
            cur.execute("""
                INSERT INTO traffic_stats (user_id, ts, proxy_bytes_in, direct_bytes_in, proxy_bytes_out, direct_bytes_out)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id, ts) DO UPDATE SET
                    proxy_bytes_in   = traffic_stats.proxy_bytes_in   + EXCLUDED.proxy_bytes_in,
                    direct_bytes_in  = traffic_stats.direct_bytes_in  + EXCLUDED.direct_bytes_in,
                    proxy_bytes_out  = traffic_stats.proxy_bytes_out  + EXCLUDED.proxy_bytes_out,
                    direct_bytes_out = traffic_stats.direct_bytes_out + EXCLUDED.direct_bytes_out
            """, (uid, ts, pb, db, pob, dob))

        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    collect()