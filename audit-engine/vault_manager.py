"""
vault_manager.py — Gerenciador de chaves Transit no HashiCorp Vault

Responsabilidades:
  - provision_key: cria chave por Pass (subject_pseudonym) — idempotente
  - encrypt_user_id: cifra id_user com a chave do Pass → ciphertext
  - destroy_key: destrói a chave permanentemente (Crypto-shredding / LGPD)

O id_user NUNCA é persistido em texto claro. Apenas o ciphertext
(vault:v1:...) entra na tabela audit_log.
"""

import os
import json
import base64
import logging

import hvac

logger = logging.getLogger(__name__)

# Prefixo de namespace para chaves Transit
KEY_PREFIX = "audit-user-"


def _load_root_token() -> str:
    """
    Carrega o root token do Vault.

    Prioridade:
      1. Variável de ambiente VAULT_TOKEN (permite override manual)
      2. Arquivo /vault/data/init.json (gerado pelo vault-init container)
    """
    token = os.environ.get("VAULT_TOKEN")
    if token:
        logger.debug("VaultManager: token carregado via VAULT_TOKEN env.")
        return token

    init_file = os.environ.get("VAULT_INIT_FILE", "/vault/data/init.json")
    logger.info(f"VaultManager: lendo token de {init_file}...")
    with open(init_file) as f:
        data = json.load(f)
    return data["root_token"]


class VaultKeyManager:
    """
    Gerencia chaves do Transit Engine no HashiCorp Vault.
    Cada subject_pseudonym (Pass) possui uma chave exclusiva.
    """

    def __init__(self):
        vault_addr = os.environ.get("VAULT_ADDR", "http://vault:8200")
        token = _load_root_token()

        self.client = hvac.Client(url=vault_addr, token=token)

        if not self.client.is_authenticated():
            raise ConnectionError(
                f"VaultManager: falha de autenticação em {vault_addr}. "
                "Verifique se o vault-init foi executado com sucesso."
            )

        logger.info(f"VaultManager: conectado e autenticado em {vault_addr}.")

    def _key_name(self, pass_id: str) -> str:
        """Mapeia subject_pseudonym → nome da chave no Transit Engine."""
        return f"{KEY_PREFIX}{pass_id}"

    def provision_key(self, pass_id: str) -> None:
        """
        Cria a chave Transit para o Pass, se ainda não existir.

        Idempotente: não falha se a chave já existe.
        Chamado antes de qualquer encrypt_user_id para garantir que a chave existe.
        """
        key_name = self._key_name(pass_id)
        try:
            self.client.secrets.transit.create_key(
                name=key_name,
                key_type="aes256-gcm96",
                # exportable=False: a chave NUNCA sai do Vault
                exportable=False,
            )
            logger.info(f"VaultManager: chave provisionada → {key_name[:24]}...")
        except hvac.exceptions.InvalidRequest:
            # Chave já existe — comportamento esperado em re-execuções
            logger.debug(f"VaultManager: chave já existia → {key_name[:24]}...")
        except Exception as e:
            logger.error(f"VaultManager: erro ao provisionar chave: {e}")
            raise

    def encrypt_user_id(self, pass_id: str, id_user: str) -> str:
        """
        Cifra o id_user usando a chave Transit do Pass.

        O Vault Transit exige plaintext em Base64.
        Retorna ciphertext no formato 'vault:v1:<base64_cifrado>'.

        IMPORTANTE: O id_user em texto claro nunca é armazenado.
        """
        plaintext_b64 = base64.b64encode(id_user.encode("utf-8")).decode("utf-8")

        response = self.client.secrets.transit.encrypt_data(
            name=self._key_name(pass_id),
            plaintext=plaintext_b64,
        )

        ciphertext = response["data"]["ciphertext"]
        logger.debug(f"VaultManager: id_user cifrado → {ciphertext[:20]}...")
        return ciphertext

    def destroy_key(self, pass_id: str) -> None:
        """
        Destrói permanentemente a chave Transit do Pass.

        Implementa o Crypto-shredding (Direito ao Esquecimento / LGPD Art. 18).
        Após esta operação:
          - Todos os logs de audit_log com este Pass ficam permanentemente
            ilegíveis (o Vault não pode mais decifrar os ciphertexts).
          - A operação é IRREVERSÍVEL.

        Deve ser chamado quando user_crypto é deletado.
        """
        key_name = self._key_name(pass_id)

        try:
            # Passo 1: Habilitar deleção (Vault exige confirmação em duas etapas)
            self.client.secrets.transit.update_key_configuration(
                name=key_name,
                deletion_allowed=True,
            )

            # Passo 2: Deletar a chave definitivamente
            self.client.secrets.transit.delete_key(name=key_name)

            logger.info(
                f"VaultManager: CRYPTO-SHREDDING concluído → chave {key_name[:24]}... destruída."
            )
        except hvac.exceptions.InvalidPath:
            # Chave já não existia — idempotente
            logger.warning(
                f"VaultManager: chave não encontrada para destruição → {key_name[:24]}..."
            )
        except Exception as e:
            logger.error(f"VaultManager: erro no crypto-shredding: {e}")
            raise
