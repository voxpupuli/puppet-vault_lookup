$d = Deferred('vault_lookup::lookup',["secret/test", 'https://vault.local:8200'])

node default {
  notify { example :
    message => $d
  }
}
