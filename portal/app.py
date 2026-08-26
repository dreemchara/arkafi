import os
#import subprocess
import re
import psycopg2
import sys
from flask import Flask, render_template, request, redirect
from getmac import get_mac_address
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from user_agents import parse


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../firewall/sync')))
from db_connection import connect_db
from captive import register_captive_routes


LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'log')
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    filename=os.path.join(LOG_DIR, 'audit.log'),
    filemode="a",
    format="%(asctime)s %(levelname)s %(message)s"
)

logging.info("Start service...")

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
)

PORTAL_IP = os.environ.get("PORTAL_IP")
PORTAL_URL = f"http://{PORTAL_IP}/"

register_captive_routes(app, PORTAL_URL)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)



#проверка логина/пароля на латиницу(разрешаем: a-z, A-Z, 0-9 длина от 3 до 20)
def is_valid_input(text):
    pattern = r'^\s*[A-Za-z0-9]+( [A-Za-z0-9]+)*\s*$'
    return re.match(pattern, text) is not None

#проверка логина
def check_login_available(cur, login, password, mac):
    cur.execute("SELECT password FROM arkafi_users WHERE login = %s;", (login,))
    row = cur.fetchone()
    if not row:
        return "available"
    saved_password = row[0].strip() if isinstance(row[0], str) else row[0]

    cur.execute("SELECT user_id FROM arkafi_users_mac WHERE mac = %s;", (mac,))
    mac_exists = cur.fetchone()
    
    if mac_exists:
        return "already_registered"
    
    if str(saved_password) == str(password):
        return "is_logging_in"
    else:
        return "wrong_password"

def get_device_name():
    user_agent = request.headers.get('User-Agent', 'Unknown')
    ua = parse(user_agent)
    
    device = ua.device.family or 'Unknown'
    os = f"{ua.os.family} {ua.os.version_string}".strip() or 'Unknown'
    browser = f"{ua.browser.family} {ua.browser.version_string}".strip() or 'Unknown'
    
    return f"{device} | {os} | {browser}"[:255]


#страница успешного входа
@app.route('/success')
def success_page():
    return render_template('success.html')


# страница входа
@app.route('/', methods=('GET', 'POST'))
def index():

    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        user_ip = request.remote_addr
        mac = get_mac_address(ip=user_ip)

        login = login.strip()
        password = password.strip()
        
        if not is_valid_input(login) or not is_valid_input(password):
            return render_template('index.html', error_msg="Доступные символы: a-z, A-Z, 0-9, длина от 3 до 20 символов")

        #print(login, password, user_ip, mac, flush=True)


        conn=connect_db()
        cur = conn.cursor()
        
        status = check_login_available(cur, login, password, mac)

        try:
            if status == "available": #регистрация
                return render_template('index.html', show_register=True)

            elif status == "is_logging_in": #вход
                cur.execute("SELECT id FROM arkafi_users WHERE login = %s;", (login,))
                user_id = cur.fetchone()[0]

                device_name = get_device_name()

                cur.execute("""
                    INSERT INTO arkafi_users_mac (user_id, mac, device_name)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id, mac) DO NOTHING;
                """, (user_id, mac, device_name))
                
                conn.commit()

                logging.info(f"Add new mac for {user_id} {login} - {mac}")
                
                #добавление макушника в ipset
#                subprocess.run(["/usr/bin/systemctl", "restart", "arkafi-firewall-sync.service"])

                return redirect(f'http://{PORTAL_IP}/success')

            elif status == "already_registered": # mac уже в белом списке
                logging.info(f"Authentication falied from mac - {mac} - already_registered")
                return render_template('index.html', regeistrations=True)
             
            elif status == "wrong_password": #не регистрация
                logging.info(f"Authentication falied from mac - {mac} - {login} not available or password is incorrect")
                return render_template('index.html', error_msg="Неверный пароль")
                                       
        except Exception as e:
            conn.rollback() # Отменяем всё, если хоть один запрос упал
            print(f"Database error: {e}")
            logging.error(f"Database error: {e}")
            return render_template('index.html', error_msg="Ошибка бд")
        finally:
            cur.close()
            conn.close()

        

    return render_template('index.html')


@app.route('/registration', methods=('GET', 'POST'))
def registration():

    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        user_ip = request.remote_addr
        mac = get_mac_address(ip=user_ip)

        login = login.strip()
        password = password.strip()
        
        if not is_valid_input(login) or not is_valid_input(password):
            return render_template('index.html', error_msg="Доступные символы: a-z, A-Z, 0-9, длина от 3 до 20 символов")

        #print(login, password, user_ip, mac, flush=True)


        conn=connect_db()
        cur = conn.cursor()
        
        status = check_login_available(cur, login, password, mac)

        try:
            if status == "available": #регистрация
                device_name = get_device_name()

                cur.execute("""
                    INSERT INTO arkafi_users (login, password)
                    VALUES (%s, %s)
                    RETURNING id;
                """, (login, password))

                user_id = cur.fetchone()[0]

                cur.execute("""
                        INSERT INTO arkafi_users_mac (user_id, mac, device_name)
                        VALUES (%s, %s, %s);
                    """, (user_id, mac, device_name))

                conn.commit()

                logging.info(f"Add new user {user_id} {login} with mac - {mac}")

                #добавление макушника в ipset
#                subprocess.run(["/usr/bin/systemctl", "restart", "arkafi-firewall-sync.service"])

                return redirect(f'http://{PORTAL_IP}/success')

            elif status == "is_logging_in":
                return render_template('registration.html', error_msg=f"Логин уже занят!")

            elif status == "already_registered": # mac уже в белом списке
                logging.info(f"Authentication falied from mac - {mac} - already_registered")
                return render_template('index.html', regeistrations=True)
             
            elif status == "wrong_password": #не регистрация
                logging.info(f"Authentication falied from mac - {mac} - {login} not available or password is incorrect")
                return render_template('registration.html', error_msg="Логин уже занят")
                                       
        except Exception as e:
            conn.rollback() # Отменяем всё, если хоть один запрос упал
            print(f"Database error: {e}")
            logging.error(f"Database error: {e}")
            return render_template('index.html', error_msg="Ошибка бд")
        finally:
            cur.close()
            conn.close()

        

    return render_template('registration.html')




if __name__ == '__main__':
    app.run(debug=True)


