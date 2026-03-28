#!/bin/bash

set -m

PROCESS_CMD="ping google.com"
WAIT_SECONDS=10
FLAG_FILE="${HOME}/flag_process_control.txt"

echo "1. Iniciando processo em background: ${PROCESS_CMD}"
ping google.com >/dev/null 2>&1 &
PID=$!
echo "P.D] ${PID}"

echo "2. Jobs atuais (jobs -l):"
jobs -l

echo "3. Aguardando ${WAIT_SECONDS}s antes de finalizar..."
sleep "${WAIT_SECONDS}"

echo "4. Enviando sinal TERM (kill ${PID})"
kill "${PID}"

sleep 1

echo "5. Verificando se o processo foi encerrado..."
if kill -0 "${PID}" 2>/dev/null; then
  echo "[ERRO] Processo ainda esta em execucao."
  ps -p "${PID}" -o pid,ppid,stat,cmd
  exit 1
else
  echo "[OK] Processo encerrado com sucesso."
fi

echo "6. Listagem final (jobs e ps):"
jobs -l || true
ps -p "${PID}" -o pid,ppid,stat,cmd || true

echo "controle_processos executado com sucesso!" > "${FLAG_FILE}"
echo "7. Flag criada em ${FLAG_FILE}"


exit 0
