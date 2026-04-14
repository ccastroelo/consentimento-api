"""
hash_chain.py — Gerenciador da corrente de integridade SHA-256

Cada registro de audit_log captura o hash SHA-256 do registro anterior,
formando uma corrente que permite detectar qualquer adulteração retroativa.

Funções principais:
  - ensure_audit_table: cria a tabela audit_log se não existir
  - load_last_hash: carrega o último hash ao iniciar o worker
  - compute_record_hash: calcula SHA-256 determinístico do registro
  - verify_chain_integrity: audita toda a corrente (uso sob demanda)
"""

import hashlib
import json
import logging

logger = logging.getLogger(__name__)

# Semente da corrente — hash do registro "gênesis" (tabela vazia)
# Valor fixo e conhecido, auditável externamente.
GENESIS_HASH = hashlib.sha256(b"audit-engine-genesis-v1").hexdigest()


def ensure_audit_table(conn) -> None:
    """
    Cria a tabela audit_log e seus índices caso não existam.
    Executado na inicialização do worker (idempotente via IF NOT EXISTS).
    """
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id                BIGSERIAL    PRIMARY KEY,
                timestamp         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                pass              TEXT         NOT NULL,
                id_user_encrypted TEXT         NOT NULL,
                event_type        TEXT         NOT NULL,
                consent_id        INTEGER,
                previous_hash     CHAR(64)     NOT NULL,
                record_hash       CHAR(64)     NOT NULL UNIQUE
            )
        """)
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_pass ON audit_log(pass)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp DESC)"
        )
    conn.commit()
    logger.info("HashChain: tabela audit_log garantida.")


def load_last_hash(conn) -> str:
    """
    Carrega o hash do último registro da corrente.

    Executado uma única vez na inicialização do worker.
    O hash é mantido em memória a partir daí — sem consulta ao banco
    a cada novo evento (benefício central da Estratégia 4).

    Retorna GENESIS_HASH se a tabela estiver vazia.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()

    last = row[0] if row else GENESIS_HASH
    logger.info(f"HashChain: último hash carregado → {last[:16]}...")
    return last


def compute_record_hash(record: dict) -> str:
    """
    Calcula SHA-256 do registro de auditoria.

    A serialização usa json.dumps com sort_keys=True para garantir
    ordem estável dos campos, tornando o hash determinístico
    independente da ordem de inserção no dict.

    O campo 'record_hash' NÃO deve estar presente em `record` ao chamar
    esta função — ele é adicionado APÓS o cálculo.
    """
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain_integrity(conn) -> dict:
    """
    Verifica a integridade de toda a corrente de logs.

    Percorre todos os registros em ordem e recomputa cada hash,
    verificando se previous_hash e record_hash são consistentes.

    Uso: auditoria periódica ou investigação forense.
    Retorna dict com 'integrity' (bool) e detalhes do primeiro erro, se houver.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, timestamp, pass, id_user_encrypted, event_type, "
            "consent_id, previous_hash, record_hash "
            "FROM audit_log ORDER BY id ASC"
        )
        rows = cur.fetchall()

    previous_hash = GENESIS_HASH
    for row in rows:
        (rid, timestamp, pass_id, id_user_encrypted, event_type,
         consent_id, stored_prev_hash, stored_record_hash) = row

        # Verifica a previous_hash
        if stored_prev_hash != previous_hash:
            return {
                "integrity": False,
                "broken_at_id": rid,
                "reason": "previous_hash não corresponde ao hash anterior",
                "expected": previous_hash,
                "found": stored_prev_hash,
            }

        # Reconstrói o registro para recomputar o hash
        record = {
            "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
            "pass": pass_id,
            "id_user_encrypted": id_user_encrypted,
            "event_type": event_type,
            "consent_id": str(consent_id) if consent_id else None,
            "previous_hash": stored_prev_hash,
        }
        expected_hash = compute_record_hash(record)

        if stored_record_hash != expected_hash:
            return {
                "integrity": False,
                "broken_at_id": rid,
                "reason": "record_hash não corresponde ao conteúdo do registro",
                "expected": expected_hash,
                "found": stored_record_hash,
            }

        previous_hash = stored_record_hash

    return {"integrity": True, "records_verified": len(rows)}
