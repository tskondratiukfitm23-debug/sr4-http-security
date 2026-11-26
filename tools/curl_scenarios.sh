#!/usr/bin/env bash
# Сценарії HTTP vs HTTPS (запускати з кореня проєкту при працюючих серверах)
set -uo pipefail
CA=server/certs/ca.crt
echo "== 1. HTTP: логін (пароль іде відкритим текстом) =="
curl -s -i -X POST -d 'username=alice&password=S3cret!' http://127.0.0.1:8081/login | tr -d '\r'
echo; echo "== 2. HTTPS: той самий логін, довіра локальному CA =="
curl -s -i --cacert $CA -X POST -d 'username=alice&password=S3cret!' https://127.0.0.1:8443/login | tr -d '\r'
echo; echo "== 3. HTTPS без довіри до CA (self-signed) -> помилка перевірки =="
curl -sS -o /dev/null https://127.0.0.1:8443/ 2>&1 | head -1
echo "== 4. Заголовки безпеки HTTPS =="
curl -s -D - -o /dev/null --cacert $CA https://127.0.0.1:8443/ | tr -d '\r'
echo "== 5. HTTP->HTTPS редирект (8080) =="
curl -sI http://127.0.0.1:8080/login | tr -d '\r' | grep -Ei '^(HTTP|location)'
echo "== 6. Цілісність: відповідь через MitM-проксі (HTTP) =="
curl -s http://127.0.0.1:8082/static/app.js; echo
echo "== 7. Застарілий клієнт TLS 1.2 -> відмова =="
curl -sS -o /dev/null --cacert $CA --tls-max 1.2 https://127.0.0.1:8443/ 2>&1 | head -1
