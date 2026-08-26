#!/bin/bash

# определяем где лежит скрипт
MY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${MY_DIR}/ru.zone"

# Используем порт из переменной окружения
PROXY_PORT=${SOCKS5_PROXY_PORT}

echo "=== Скачивание актуального списка IP-адресов ==="
# Скачиваем файл во временное место, чтобы не сломать старый файл, если скачивание оборвется
TMP_ZONE_FILE="${OUTPUT_FILE}.tmp"

if curl -s -x socks5://127.0.0.1:"${PROXY_PORT}" -o "${TMP_ZONE_FILE}" https://www.ipdeny.com/ipblocks/data/countries/ru.zone; then
    # Если скачалось успешно и файл не пустой — заменяем старый файл
    if [ -s "${TMP_ZONE_FILE}" ]; then
        mv "${TMP_ZONE_FILE}" "${OUTPUT_FILE}"
        echo "Файл ru.zone успешно обновлен в: ${OUTPUT_FILE}"
    else
        echo "Ошибка: Скачанный файл пуст"
        rm -f "${TMP_ZONE_FILE}"
    fi
else
    echo "Ошибка: Не удалось скачать файл через прокси (порт ${PROXY_PORT})."
    rm -f "${TMP_ZONE_FILE}"
fi

echo "=== Шаг 2: Загрузка списка в ipset ==="
# Проверяем, существует ли файл (новый или оставшийся с прошлого раза)
if [ ! -s "${OUTPUT_FILE}" ]; then
    echo "Ошибка: Файл ${OUTPUT_FILE} отсутствует или пуст. Обновление ipset прервано."
    exit 1
fi

# Создаем временный список в памяти, чтобы не прерывать работу сети
ipset create runetlist_tmp hash:net -exist
ipset flush runetlist_tmp

# Быстро заливаем адреса из файла в ipset
{
  echo "create runetlist_tmp hash:net -exist"
  sed "s/^/add runetlist_tmp /" "${OUTPUT_FILE}"
} | ipset restore

# Создаем основной список, если его еще не было
ipset create runetlist hash:net -exist

# свап
ipset swap runetlist_tmp runetlist

# Удаляем временный список
ipset destroy runetlist_tmp

echo "ipset 'runetlist' успешно обновлен"
