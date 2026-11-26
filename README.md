# СР №4. Безпека мережевого протоколу HTTP/1.1 → HTTPS (TLS 1.3)

Автор: Кондратюк Т.С., група 22340, КУБГ.

Демо-стенд: вразливий HTTP-сервер, захищений HTTPS-сервер (TLS 1.3, HSTS, CSP, захищені cookie,
rate-limit), сніфер облікових даних, MitM-проксі, заміри продуктивності.

## Структура
| Файл | Призначення |
|---|---|
| `server/insecure_app.py` | HTTP :8081 — форма логіну, Basic, echo, cookie без прапорців |
| `server/secure_app.py` | ті самі ендпоінти + заголовки безпеки, `__Host-` cookie, rate-limit 5/60 с |
| `server/security_headers.py` | HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| `server/run_secure.py` | запуск HTTPS :8443 лише з TLS 1.3; `--redirect` — HTTP :8080 → 301 HTTPS |
| `server/scripts/gencerts.sh` | локальний CA + серверний сертифікат з SAN (localhost, 127.0.0.1) |
| `tools/sniff_http_creds.py` | Scapy-сніфер Basic/форм/cookie |
| `tools/mitm_proxy.py` | MitM-проксі :8082, підміна HTML/JS у HTTP-відповідях |
| `tools/curl_scenarios.sh` | сценарії HTTP vs HTTPS |
| `tools/tls_check.sh` | перевірка версій TLS |
| `tools/bench.py` | latency/RPS/CPU HTTP vs HTTPS |
| `tests/test_apps.py` | pytest-перевірки заголовків, cookie, rate-limit |

## Запуск
```bash
pip install -r requirements.txt
bash server/scripts/gencerts.sh
uvicorn server.insecure_app:app --host 127.0.0.1 --port 8081   # вікно 1
python -m server.run_secure                                     # вікно 2 (HTTPS 8443)
python -m server.run_secure --redirect                          # вікно 3 (HTTP 8080 -> HTTPS)
python tools/mitm_proxy.py                                      # вікно 4 (MitM 8082)
sudo python tools/sniff_http_creds.py --iface lo --port 8081    # вікно 5
bash tools/curl_scenarios.sh && bash tools/tls_check.sh && python tools/bench.py
pytest -q
```
Стенд призначений лише для loopback-інтерфейсу; не запускайте сніфер у чужих мережах.
