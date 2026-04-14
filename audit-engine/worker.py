"""
worker.py — Audit Engine (Estratégia 4: Worker + Redis Stream)

Fluxo principal:
  1. Conecta ao PostgreSQL, Redis e Vault
  2. Garante que a tabela audit_log existe
  3. Carrega o último hash da corrente em memória
  4. Consome eventos do Redis Stream 'audit:consent_events' (blocking)
  5. Para cada evento:
     - USER_FORGOTTEN → crypto-shredding da chave no Vault (sem log)
     - CONSENT_CREATED / CONSENT_REVOKED → cifra id_user, encadeia hash,
       persiste em audit_log
     - XACK apenas após commit bem-sucedido (sem perda silenciosa)

Garantias:
  - id_user NUNCA toca o banco em texto claro
  - Hash chain NUNCA é quebrada (single-threaded, hash em memória)
  - Falhas de processamento não avançam o ponteiro da stream (XACK só pós-commit)
"""

import os
import time
import logging
from datetime import datetime, timezone

import psycopg2
import redis as redis_lib

from vault_manager import VaultKeyManager
from hash_chain import (
    ensure_audit_table,
    load_last_hash,
    compute_record_hash,
)

# --- Configuração de Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("audit-worker")

# --- Constantes do Redis Stream ---
STREAM_KEY = "audit:consent_events"
CONSUMER_GROUP = "audit-engine-group"
CONSUMER_NAME = "worker-1"

# Eventos que geram registro de auditoria na tabela
AUDITABLE_EVENTS = {"CONSENT_CREATED", "CONSENT_REVOKED"}


# ---------------------------------------------------------------------------
# Conexões
# ---------------------------------------------------------------------------

def connect_db(retries: int = 15, delay: int = 3) -> psycopg2.extensions.connection:
    """Conecta ao PostgreSQL com retry para aguardar o healthcheck do container."""
    db_url = os.environ["DATABASE_URL"]
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(db_url)
            conn.autocommit = False
            logger.info("DB: conexão estabelecida.")
            return conn
        except psycopg2.OperationalError as e:
            logger.warning(f"DB: tentativa {attempt}/{retries} falhou: {e}")
            if attempt < retries:
                time.sleep(delay)
    raise RuntimeError("DB: não foi possível conectar após todas as tentativas.")


def connect_redis(retries: int = 10, delay: int = 3) -> redis_lib.Redis:
    """Conecta ao Redis com retry."""
    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379")
    for attempt in range(1, retries + 1):
        try:
            r = redis_lib.from_url(redis_url, decode_responses=False)
            r.ping()
            logger.info(f"Redis: conexão estabelecida em {redis_url}.")
            return r
        except redis_lib.exceptions.ConnectionError as e:
            logger.warning(f"Redis: tentativa {attempt}/{retries} falhou: {e}")
            if attempt < retries:
                time.sleep(delay)
    raise RuntimeError("Redis: não foi possível conectar após todas as tentativas.")


def ensure_consumer_group(r: redis_lib.Redis) -> None:
    """Cria o consumer group se não existir. mkstream=True cria a stream se necessário."""
    try:
        r.xgroup_create(STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info(f"Redis: consumer group '{CONSUMER_GROUP}' criado.")
    except redis_lib.exceptions.ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.info(f"Redis: consumer group '{CONSUMER_GROUP}' já existia.")
        else:
            raise


# ---------------------------------------------------------------------------
# Processamento de Eventos
# ---------------------------------------------------------------------------

def process_event(
    data: dict,
    vault: VaultKeyManager,
    conn: psycopg2.extensions.connection,
    last_hash: str,
) -> str:
    """
    Processa um único evento da stream e retorna o novo last_hash.

    Para USER_FORGOTTEN: executa crypto-shredding e retorna last_hash inalterado.
    Para eventos auditáveis: cifra id_user, encadeia hash, persiste no banco.
    """
    event_type = data[b"event_type"].decode()
    pass_id = data[b"pass"].decode()
    id_user = data[b"id_user"].decode()
    consent_id_raw = data.get(b"consent_id", b"").decode() or None

    # --- Crypto-shredding ---
    if event_type == "USER_FORGOTTEN":
        logger.info(f"Worker: USER_FORGOTTEN → iniciando crypto-shredding para pass={pass_id[:12]}...")
        vault.destroy_key(pass_id)
        # Não gera registro de log — o esquecimento não deve ser rastreável
        return last_hash

    # --- Evento auditável ---
    if event_type not in AUDITABLE_EVENTS:
        logger.warning(f"Worker: tipo de evento desconhecido '{event_type}' — ignorado.")
        return last_hash

    # Passo 1: Garante que a chave existe no Vault (idempotente)
    vault.provision_key(pass_id)

    # Passo 2: Cifra o id_user — a partir daqui, id_user em claro não é mais usado
    encrypted_id = vault.encrypt_user_id(pass_id, id_user)

    # Passo 3: Monta o registro de log (SEM id_user em claro)
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "timestamp": timestamp,
        "pass": pass_id,
        "id_user_encrypted": encrypted_id,
        "event_type": event_type,
        "consent_id": consent_id_raw,
        "previous_hash": last_hash,
        # record_hash será adicionado após compute
    }

    # Passo 4: Calcula o hash do registro atual (encadeia com o anterior)
    record_hash = compute_record_hash(record)
    record["record_hash"] = record_hash

    # Passo 5: Persiste no banco — DENTRO DE UMA TRANSAÇÃO
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO audit_log
                (timestamp, pass, id_user_encrypted, event_type,
                 consent_id, previous_hash, record_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                timestamp,
                pass_id,
                encrypted_id,
                event_type,
                int(consent_id_raw) if consent_id_raw else None,
                last_hash,
                record_hash,
            ),
        )
    conn.commit()

    logger.info(
        f"Worker: auditado → event={event_type} "
        f"pass={pass_id[:12]}... "
        f"hash={record_hash[:16]}..."
    )

    # Retorna o novo hash para atualização em memória
    return record_hash


# ---------------------------------------------------------------------------
# Loop Principal
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 60)
    logger.info("Audit Engine iniciando (Estratégia 4 — Worker + Redis Stream)")
    logger.info("=" * 60)

    # Conexões
    db_conn = connect_db()
    redis_client = connect_redis()
    vault = VaultKeyManager()

    # Inicialização da tabela e da corrente
    ensure_audit_table(db_conn)
    ensure_consumer_group(redis_client)

    last_hash = load_last_hash(db_conn)
    logger.info(f"Worker: corrente iniciada. last_hash={last_hash[:16]}...")
    logger.info("Worker: aguardando eventos na stream 'audit:consent_events'...")

    while True:
        try:
            # XREADGROUP com block=5000ms — libera a GIL enquanto aguarda
            messages = redis_client.xreadgroup(
                CONSUMER_GROUP,
                CONSUMER_NAME,
                {STREAM_KEY: ">"},  # '>' = apenas mensagens não entregues
                block=5000,
                count=1,           # 1 evento por vez — garante serialização do hash chain
            )

            if not messages:
                continue

            for _stream, events in messages:
                for event_id, data in events:
                    try:
                        last_hash = process_event(data, vault, db_conn, last_hash)
                        # XACK apenas após commit bem-sucedido
                        redis_client.xack(STREAM_KEY, CONSUMER_GROUP, event_id)

                    except Exception as e:
                        logger.error(
                            f"Worker: ERRO ao processar evento {event_id}: {e}",
                            exc_info=True,
                        )
                        # Não faz XACK — Redis irá reentregareste evento
                        db_conn.rollback()

        except redis_lib.exceptions.ConnectionError as e:
            logger.error(f"Worker: perda de conexão com Redis: {e}. Reconectando em 5s...")
            time.sleep(5)
            redis_client = connect_redis()

        except psycopg2.OperationalError as e:
            logger.error(f"Worker: perda de conexão com DB: {e}. Reconectando em 5s...")
            time.sleep(5)
            db_conn = connect_db()
            last_hash = load_last_hash(db_conn)  # Recarrega hash após reconexão


if __name__ == "__main__":
    main()
