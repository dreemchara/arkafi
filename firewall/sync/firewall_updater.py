import psycopg2
import subprocess

from traffic_collector import read_dnsmasq_leases
from db_connection import connect_db

def sync():
    try:
        conn = connect_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT m.mac 
            FROM arkafi_users_mac m 
            JOIN arkafi_users u ON m.user_id = u.id 
            WHERE u.status = 't';
        """)
        active_macs = [row[0].lower() for row in cur.fetchall()]
        
        #основной список разрешённных мак адресов
        subprocess.run(["/usr/sbin/ipset", "create", "-!", "allowed_macs", "hash:mac"])
            #основной список разрешённных ip
        subprocess.run(["/usr/sbin/ipset", "create", "-!", "allowed_ips", "hash:ip"])


        #временный список новых адресов
        subprocess.run(["/usr/sbin/ipset", "create", "-!", "tmp_macs", "hash:mac"])
        subprocess.run(["/usr/sbin/ipset", "flush", "tmp_macs"])
            # и ip
        subprocess.run(["/usr/sbin/ipset", "create", "-!", "tmp_ips", "hash:ip"])
        subprocess.run(["/usr/sbin/ipset", "flush", "tmp_ips"])


        ip_to_mac = read_dnsmasq_leases()

        active_macs_lower = {mac.lower() for mac in active_macs}
        active_ips = [ip for ip, mac in ip_to_mac.items() if mac.lower() in active_macs_lower]

        
        #добавление мак адресов в список
        for mac in active_macs:
            subprocess.run(["/usr/sbin/ipset", "add", "tmp_macs", mac])

        #добавление ip адресов в список
        for ip in active_ips:
            subprocess.run(["/usr/sbin/ipset", "add", "tmp_ips", ip])

        #замена временного списка на новый    
        subprocess.run(["/usr/sbin/ipset", "swap", "tmp_macs", "allowed_macs"])
                #замена временного списка на новый    
        subprocess.run(["/usr/sbin/ipset", "swap", "tmp_ips", "allowed_ips"])

        #очыыстка дада очыыыыстка счееетчиков для мок одресов
        subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-F", "ACCT_PROXY_IN"])
        subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-F", "ACCT_DIRECT_IN"])
        subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-F", "ACCT_PROXY_OUT"])
        subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-F", "ACCT_DIRECT_OUT"])
        
        ##-- добавление счётчиков для мак адресов
            # входящие
        for mac in active_macs:
            subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-I", "ACCT_PROXY_IN", "1", "-m", "mac", "--mac-source", mac, "-j", "RETURN"])
            subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-I", "ACCT_DIRECT_IN", "1", "-m", "mac", "--mac-source", mac, "-j", "RETURN"])


            # исходящие
        for ip in active_ips:
            subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-I", "ACCT_PROXY_OUT",  "1", "-d", ip, "-j", "RETURN"])
            subprocess.run(["/usr/sbin/iptables", "-t", "mangle", "-I", "ACCT_DIRECT_OUT", "1", "-d", ip, "-j", "RETURN"])


        subprocess.run(["/usr/sbin/ipset", "destroy", "tmp_macs"])
        
        cur.close()
        conn.close()
        print(f"Синхронизировано {len(active_macs)} устройств")
        
    except Exception as e:
        print(f"Ошибка: {e}")

if __name__ == "__main__":
    sync()