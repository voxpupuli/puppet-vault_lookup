# @summary Fetches secret stored under $key from Vault $server
# @param key
# @param server Either server address or Hiera key to lookup Vault server address
function vault_lookup::kv(String $key, String $server = 'vault_lookup::server') >> Deferred {
  $_vault = $server =~ /^http/ ? {
    true => $server,
    false => lookup($server)
  }
  Deferred(
    'vault_lookup::lookup',
    [$key, $_vault]
  )
}
