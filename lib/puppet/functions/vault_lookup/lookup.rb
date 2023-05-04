# frozen_string_literal: true

require_relative '../../../puppet_x/vault_lookup/lookup'

Puppet::Functions.create_function(:'vault_lookup::lookup', Puppet::Functions::InternalFunction) do
  dispatch :lookup do
    cache_param
    param 'String', :path
    optional_param 'String', :vault_addr
    optional_param 'Optional[String]', :cert_path_segment
    optional_param 'String', :cert_role
    optional_param 'String', :namespace
    optional_param 'String', :field
    optional_param 'Enum["cert", "approle", "agent", "agent_sink"]', :auth_method
    optional_param 'String', :role_id
    optional_param 'String', :secret_id
    optional_param 'Optional[String]', :approle_path_segment
    optional_param 'String', :agent_sink_file
    return_type 'Sensitive'
  end

  # Allows for passing a hash of options to the vault_lookup::lookup() function.
  #
  # @example
  #  $foo = vault::lookup('secret/some/path/foo',
  #    {'vault_addr' => 'https://vault.corp.net:8200', 'auth_method' => 'cert'}
  #  )
  #
  dispatch :lookup_opts_hash do
    cache_param
    param 'String[1]', :path
    param 'Hash[String[1], Data]', :options
    return_type 'Sensitive'
  end

  # Lookup with a path and an options hash.
  def lookup_opts_hash(cache, path, options = {})
    # NOTE: The order of these options MUST be the same as the lookup()
    # function's signature. If new parameters are added to lookup(), or if the
    # order of existing parameters change, those changes must also be made
    # here.
    PuppetX::VaultLookup::Lookup.lookup(cache: cache,
                                        path: path,
                                        vault_addr: options['vault_addr'],
                                        cert_path_segment: options['cert_path_segment'],
                                        cert_role: options['cert_role'],
                                        namespace: options['namespace'],
                                        field: options['field'],
                                        auth_method: options['auth_method'],
                                        role_id: options['role_id'],
                                        secret_id: options['secret_id'],
                                        approle_path_segment: options['approle_path_segment'],
                                        agent_sink_file: options['agent_sink_file'])
  end

  # Lookup with a path and positional arguments.
  # NOTE: If new parameters are added, or if the order of existing parameters
  # change, those changes must also be made to the lookup() call in
  # lookup_opts_hash().
  def lookup(cache,
             path,
             vault_addr = nil,
             cert_path_segment = nil,
             cert_role = nil,
             namespace = nil,
             field = nil,
             auth_method = nil,
             role_id = nil,
             secret_id = nil,
             approle_path_segment = nil,
             agent_sink_file = nil)

    PuppetX::VaultLookup::Lookup.lookup(cache: cache,
                                        path: path,
                                        vault_addr: vault_addr,
                                        cert_path_segment: cert_path_segment,
                                        cert_role: cert_role,
                                        namespace: namespace,
                                        field: field,
                                        auth_method: auth_method,
                                        role_id: role_id,
                                        secret_id: secret_id,
                                        approle_path_segment: approle_path_segment,
                                        agent_sink_file: agent_sink_file)
  end
end
