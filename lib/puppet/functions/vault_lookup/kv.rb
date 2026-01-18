# frozen_string_literal: true

Puppet::Functions.create_function('vault_lookup::kv') do
  # @summary Fetches secret stored under $key from Vault server using deferred function
  # @param key Secret key path in Vault
  # @param ops Options passed to Vault
  #
  # kv2 is prefixed with `"kv/data`
  #
  # @example
  #  vault::kv('secret')
  #  vault::kv('secret', {'field' => 'password'})
  dispatch :kv do
    param 'String', :key
    optional_param 'Hash', :opts
    return_type 'Deferred'
  end

  def kv(key, opts = {})
    unless opts.key?('vault_addr')
      type_parser = Puppet::Pops::Types::TypeParser.singleton
      vault_addr = call_function('lookup', 'vault_lookup::server', type_parser.parse('Optional[String]'), nil, nil)
      opts['vault_addr'] = vault_addr if vault_addr
    end

    Puppet::Pops::Types::TypeFactory.deferred.create('vault_lookup::lookup', [key, opts])
  end
end
