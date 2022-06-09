#!/bin/sh
set -e

export VAULT_ADDR=https://vault.local:8200
export VAULT_CLIENT_KEY=/vault/config/vault.key
export VAULT_CLIENT_CERT=/vault/config/vault.cert
export VAULT_CACERT=/vault/config/certbundle.pem
echo "Initialize Vault"
vault operator init -key-shares=1 -key-threshold=1 | tee vault.keys
VAULT_TOKEN=$(grep '^Initial' vault.keys | awk '{print $4}')
VAULT_KEY=$(grep '^Unseal Key 1:' vault.keys | awk '{print $4}')

export VAULT_TOKEN

vault operator unseal "$VAULT_KEY"

echo "Create secret_reader policy that can read from kv/*"

vault policy write secret_reader - <<EOF
path "kv/*" {
    capabilities = ["read"]
}
EOF

echo "Enable cert auth and add puppet server CA for secret_reader"
echo "Adding cert auth paths."

vault auth enable cert

vault write auth/cert/certs/vault.docker display_name='puppet cert' certificate=@/vault/config/certbundle.pem token_policies=secret_reader

echo 'Write secret/test: foo=bar'
vault secrets enable -version=1 kv
vault kv put kv/test foo=bar
