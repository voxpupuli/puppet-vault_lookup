{
  "disable_mlock": true,
  "backend": {
    "file": {
      "path": "/vault/file"
    }
  },
  "listener": {
    "tcp": {
      "address": "0.0.0.0:8200",
      "tls_key_file": "/vault/config/vault.key",
      "tls_cert_file": "/vault/config/vault.cert",
      "tls_client_ca_file": "/vault/config/certbundle.pem"
    }
  }
}
