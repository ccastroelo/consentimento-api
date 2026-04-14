# Vault — File Storage Configuration
# Chaves Transit são persistidas no volume Docker vault_data
# montado em /vault/data. Sobrevivem a restarts do container.

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1   # TLS desabilitado para PoC local. Habilitar em produção.
}

# Endereço anunciado para outros serviços na rede Docker
api_addr = "http://vault:8200"

# UI desabilitada — acesso apenas via CLI/API
ui = false
