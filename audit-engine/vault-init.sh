#!/bin/sh
# vault-init.sh — Container one-shot para inicialização e unseal do Vault
#
# Executado pelo serviço vault-init após o Vault estar respondendo.
# Responsabilidades:
#   1. Aguardar Vault estar online
#   2. Inicializar (apenas na primeira execução) — gera unseal key + root token
#   3. Armazenar init.json no volume compartilhado vault_data
#   4. Unseal o Vault (necessário em todo restart)
#   5. Habilitar o Transit secrets engine (idempotente)

set -e

echo "[vault-init] Aguardando Vault responder em $VAULT_ADDR..."
until vault status 2>&1 | grep -q "Seal Type"; do
  echo "[vault-init] Vault ainda não está pronto. Tentando novamente em 3s..."
  sleep 3
done

echo "[vault-init] Vault está respondendo."

# --- Passo 1: Verificar se já foi inicializado ---
IS_INIT=$(vault status 2>&1 | grep "Initialized" | awk '{print $2}')

if [ "$IS_INIT" = "false" ]; then
  echo "[vault-init] Primeira execução: inicializando Vault..."
  # 1 key share + 1 threshold = simplicidade para PoC
  # Em produção: use múltiplos shares e threshold > 1
  vault operator init \
    -key-shares=1 \
    -key-threshold=1 \
    -format=json > /vault/data/init.json
  echo "[vault-init] Vault inicializado. Chaves salvas em /vault/data/init.json"
else
  echo "[vault-init] Vault já foi inicializado anteriormente. Carregando chaves de /vault/data/init.json"
fi

# --- Passo 2: Parsear init.json ---
# Colapsa JSON em uma linha para simplificar o sed
JSON=$(cat /vault/data/init.json | tr -d '\n' | tr -s ' ')

UNSEAL_KEY=$(echo "$JSON" | sed 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/')
ROOT_TOKEN=$(echo "$JSON" | sed 's/.*"root_token":"\([^"]*\)".*/\1/')

if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
  echo "[vault-init] ERRO: Não foi possível parsear init.json"
  exit 1
fi

# --- Passo 3: Unseal ---
echo "[vault-init] Realizando unseal..."
vault operator unseal "$UNSEAL_KEY"
echo "[vault-init] Vault desselado com sucesso."

# --- Passo 4: Habilitar Transit Engine ---
echo "[vault-init] Habilitando Transit secrets engine..."
VAULT_TOKEN="$ROOT_TOKEN" vault secrets enable transit 2>/dev/null \
  && echo "[vault-init] Transit habilitado." \
  || echo "[vault-init] Transit já estava habilitado."

echo "[vault-init] Vault pronto. Encerrando container de inicialização."
