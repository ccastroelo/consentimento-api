"""
worker.py — Privacy Cleanup Worker (Right to be Forgotten)

Este worker executa periodicamente para:
1. Identificar usuários marcados como 'pending_deletion'.
2. Executar Crypto-shredding (destruição da chave no Vault).
3. Gerar um evento 'Tombstone' na cadeia de hashes de consentimento.
4. Realizar a deleção física do registro UserCrypto (removendo o salt).
"""

import time
import hashlib
import logging
from datetime import datetime
from app import db, app, UserCrypto, Consents, generate_pseudonym

# Configuração de Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privacy-worker")

def process_pending_deletions():
    """
    Varre a tabela UserCrypto em busca de usuários marcados para deleção.
    """
    with app.app_context():
        # Busca usuários marcados para deleção
        pending_users = UserCrypto.query.filter_by(pending_deletion=True).all()
        
        if not pending_users:
            return

        logger.info(f"Worker: Encontrados {len(pending_users)} usuários para processar.")
        
        for user in pending_users:
            user_id = user.id_user
            try:
                # 2. Reconstruir o pseudônimo ANTES de apagar o registro
                pseudonym = generate_pseudonym(user.id_user, user.salt)
                
                # 3. Gerar Evento 'Tombstone' na Cadeia de Hashes
                # Busca o último hash do usuário para manter a integridade da corrente.
                last_consent = Consents.query.filter_by(subject_pseudonym=pseudonym).order_by(Consents.id.desc()).first()
                parent_hash = last_consent.validation_hash if last_consent else None
                
                timestamp = datetime.utcnow()
                # O hash do evento de esquecimento encadeia o estado anterior
                hash_input = f"{pseudonym}:USER_FORGOTTEN:{timestamp.isoformat()}:{parent_hash}"
                tombstone_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
                
                tombstone = Consents(
                    subject_pseudonym=pseudonym,
                    id_policy=None, # Evento de sistema, não atrelado a nenhuma política
                    channel="system",
                    validation_hash=tombstone_hash,
                    created_at=timestamp,
                    status="forgotten",
                    parent_hash=parent_hash,
                    sequence_version=user.version
                )
                db.session.add(tombstone)
                
                # 4. Deleção Física do Registro Criptográfico
                # Remove o salt definitivamente do banco de dados.
                db.session.delete(user)
                
                db.session.commit()
                logger.info(f"Worker: Direito ao Esquecimento concluído para user_id={user_id}.")
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Worker: Erro ao processar user_id={user_id}: {e}")

if __name__ == "__main__":
    logger.info("Worker de Privacidade iniciado. Varrendo base a cada 60 segundos...")
    while True:
        try:
            process_pending_deletions()
        except Exception as e:
            logger.error(f"Worker: Erro no loop principal: {e}")
        
        # Intervalo de varredura (ajustável)
        time.sleep(60)
