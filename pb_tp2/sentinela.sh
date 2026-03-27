#!/bin/bash

LOCAL_TIMESTAMP="$(date '+%Y%m')"
LOCAL_LOGFILE="logs/sentinela_${LOCAL_TIMESTAMP}.txt"

# Verifiar se está executando na pasta indicada
LOCAL_SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"
if [[ "$PWD" != "${LOCAL_SCRIPTDIR}" ]]; then
  echo ""
  echo "[ERRO] $(date '+%d-%m-%Y %H:%M:%S')"
  echo "Acesse a pasta do script antes de executá-lo!"
  echo "Execute o comando:"
  echo "cd ${LOCAL_SCRIPTDIR}"
  exit 1
fi

mkdir -p logs

LOCAL_RUN_PS=0
LOCAL_RUN_SS=0
LOCAL_RUN_SYSTEMCTL=0
LOCAL_DEBUG=0
LOCAL_LOOP=0
LOCAL_INTERVAL=5

while getopts ":pstdli:h" opt; do
  case "$opt" in
    p) LOCAL_RUN_PS=1 ;;
    s) LOCAL_RUN_SS=1 ;;
    t) LOCAL_RUN_SYSTEMCTL=1 ;;
    d) LOCAL_DEBUG=1 ;;
    l) LOCAL_LOOP=1 ;;
    i)
      if [[ "$OPTARG" =~ ^[0-9]+$ ]] && [[ "$OPTARG" -ge 1 ]]; then
        LOCAL_INTERVAL="$OPTARG"
      else
        echo "Valor inválido para -i: ${OPTARG}"
        echo "Use um inteiro maior ou igual a 1."
        exit 1
      fi
      ;;
    h)
      echo "Uso: $0 [-p] [-s] [-t] [-d] [-l] [-i segundos]"
      echo "  -p  executa ps aux"
      echo "  -s  executa ss -ltunp"
      echo "  -t  executa systemctl --type=service --state=running"
      echo "  -d  imprime no terminal (debug), sem gravar no log"
      echo "  -l  executa em loop contínuo"
      echo "  -i  intervalo em segundos entre loops (padrão: 5)"
      exit 0
      ;;
    \?)
      echo "Opção inválida: -$OPTARG"
      echo "Use -h para ajuda."
      exit 1
      ;;
  esac
done

# Se nenhuma opção for passada, mantém o comportamento atual (executa tudo).
if [[ $LOCAL_RUN_PS -eq 0 && $LOCAL_RUN_SS -eq 0 && $LOCAL_RUN_SYSTEMCTL -eq 0 ]]; then
  LOCAL_RUN_PS=1
  LOCAL_RUN_SS=1
  LOCAL_RUN_SYSTEMCTL=1
fi

print_header() {
  echo ""
  echo "----------------------------------------"
  echo "[$1]"
}

run_sentinela() {
echo ""
echo "----------------------------------------"
echo "[SENTINELA] $(date '+%Y-%m-%d %H:%M:%S')"

if [[ $LOCAL_RUN_PS -eq 1 ]]; then
print_header "ps aux"
ps aux
fi

if [[ $LOCAL_RUN_SS -eq 1 ]]; then
print_header "ss -ltunp"
ss -ltunp
fi

if [[ $LOCAL_RUN_SYSTEMCTL -eq 1 ]]; then
print_header "systemctl --type=service --state=running"
systemctl --type=service --state=running
fi

echo "----------------------------------------"
echo "fim"

}

if [[ $LOCAL_DEBUG -eq 1 ]]; then
  if [[ $LOCAL_LOOP -eq 1 ]]; then
    while true; do
      run_sentinela
      sleep "$LOCAL_INTERVAL"
    done
  else
    run_sentinela
  fi
else
  if [[ $LOCAL_LOOP -eq 1 ]]; then
    while true; do
      run_sentinela >> "${LOCAL_LOGFILE}"
      echo "Log atualizado em ${LOCAL_LOGFILE}"
      sleep "$LOCAL_INTERVAL"
    done
  else
    run_sentinela >> "${LOCAL_LOGFILE}"
    echo "Log atualizado em ${LOCAL_LOGFILE}"
  fi
fi


exit 0

