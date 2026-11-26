#!/usr/bin/env bash
# Перевірка політики TLS сервера (за замовч. 127.0.0.1:8443).
# Клієнт навмисно знижує свій рівень безпеки (SECLEVEL=0), щоб відмову фіксував саме сервер.
PORT=${1:-8443}; CA=server/certs/ca.crt
for v in tls1 tls1_1 tls1_2 tls1_3; do
  out=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:$PORT -$v -cipher 'DEFAULT@SECLEVEL=0' -CAfile $CA 2>&1)
  if echo "$out" | grep -q "^New, TLS"; then
    echo "[$v] ПРИЙНЯТО: $(echo "$out" | grep -m1 '^New,') | $(echo "$out" | grep -m1 'Verify return code')"
  else
    echo "[$v] ВІДХИЛЕНО сервером: $(echo "$out" | grep -m1 -Eo 'unexpected eof|alert [a-z ]+|wrong version number' || echo handshake failure)"
  fi
done
