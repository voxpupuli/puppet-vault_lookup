# @summary Fetches secret stored under $key from Vault server using deferred function
# @param key Secret key path in Vault
# @param ops Options passed to Vault
#
# @example
#  vault_lookup::kv('secret')
#  vault_lookup::kv('secret', {'vault_addr' => 'http://vault:8200'})

function vault_lookup::kv(String $key, Hash $opts = {}) >> Deferred {
  $_opts = if 'vault_addr' in $opts {
    $opts
  } else {
    $_vault = lookup('vault_lookup::server', Optional[String], undef, undef)
    if $_vault {
      $opts + { 'vault_addr' => $_vault }
    } else {
      $opts
    }
  }
  Deferred(
    'vault_lookup::lookup',
    [$key, $_opts]
  )
}
