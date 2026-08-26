import psycopg2
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
CONF_PATH = BASE_DIR / 'config' / 'firewall.conf'

if CONF_PATH.exists():
    load_dotenv(dotenv_path=CONF_PATH)
else:
    print(f"Ошибка: Файл конфигурации не найден по пути {CONF_PATH}")


db_config = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
    }

def connect_db():
    return psycopg2.connect(**db_config)


if __name__ == "__main__":
    print(f"Пытаюсь подключиться к БД '{db_config['dbname']}' на {db_config['host']}...")
    conn = connect_db(db_config)
    if conn:
        print("Успешное подключение!")
        conn.close()