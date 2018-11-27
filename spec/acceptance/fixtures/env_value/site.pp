$d = Deferred('vault_lookup::lookup',["secret/test"])

node default {
  notify { "example with env lookup":
    message => $d
  }
}
