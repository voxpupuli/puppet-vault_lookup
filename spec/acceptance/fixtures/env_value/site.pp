$var = {
  'd' => Deferred('vault_lookup::lookup', ["kv/test"])
}

node default {
  file { '/root/secret.txt':
    ensure  => present,
    content => Deferred('inline_epp', ['<%= $d.unwrap.convert_to(Array).flatten() %>', $var])
  }
}
