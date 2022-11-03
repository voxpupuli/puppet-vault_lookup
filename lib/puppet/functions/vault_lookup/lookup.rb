Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup do
    param 'String', :path
    optional_param 'String', :vault_addr
    optional_param 'Optional[String]', :cert_path_segment
    optional_param 'String', :cert_role
    optional_param 'String', :namespace
    optional_param 'String', :field
    optional_param 'Enum["cert", "approle"]', :auth_method
    optional_param 'String', :role_id
    optional_param 'String', :secret_id
    optional_param 'Optional[String]', :approle_path_segment
    return_type 'Sensitive'
  end

  dispatch :lookup_opts_hash do
    # Allows for passing a hash of options to the vault::vault_lookup() function.
    #
    # @example
    #  $foo = vault::lookup('secret/some/path/foo',
    #    {'vault_addr' => 'https://vault.corp.net:8200', 'auth_method' => 'cert'}
    #  )
    #
    param 'String[1]', :path
    param 'Hash[String[1], Data]', :options
    return_type 'Sensitive'
  end

  # Lookup with a path and an options hash.
  def lookup_opts_hash(path, options = {})
    # NOTE: The order of these options MUST be the same as the lookup()
    # function's signature. If new parameters are added to lookup(), or if the
    # order of existing parameters change, those changes must also be made
    # here.
    lookup(path,
           options['vault_addr'],
           options['cert_path_segment'],
           options['cert_role'],
           options['namespace'],
           options['field'],
           options['auth_method'],
           options['role_id'],
           options['secret_id'],
           options['approle_path_segment'])
  end

  DEFAULT_CERT_PATH_SEGMENT = 'v1/auth/cert/'.freeze
  DEFAULT_APPROLE_PATH_SEGMENT = 'v1/auth/approle/'.freeze

  # Lookup with a path and positional arguments.
  # NOTE: If new parameters are added, or if the order of existing parameters
  # change, those changes must also be made to the lookup() call in
  # lookup_opts_hash().
  def lookup(path,
             vault_addr = nil,
             cert_path_segment = nil,
             cert_role = nil,
             namespace = nil,
             field = nil,
             auth_method = nil,
             role_id = nil,
             secret_id = nil,
             approle_path_segment = nil)

    if auth_method.nil?
      auth_method = ENV['VAULT_AUTH_METHOD'] || 'cert'
    end

    if vault_addr.nil?
      Puppet.debug 'No Vault address was set on function, defaulting to value from VAULT_ADDR env value'
      vault_addr = ENV['VAULT_ADDR']
      raise Puppet::Error, 'No vault_addr given and VAULT_ADDR env variable not set' if vault_addr.nil?
    end
    if namespace.nil?
      Puppet.debug 'No Vault namespace was set on function, defaulting to value from VAULT_NAMESPACE env value'
      namespace = ENV['VAULT_NAMESPACE']
    end

    if role_id.nil?
      role_id = ENV['VAULT_ROLE_ID']
    end

    if secret_id.nil?
      secret_id = ENV['VAULT_SECRET_ID']
    end

    if cert_path_segment.nil?
      cert_path_segment = DEFAULT_CERT_PATH_SEGMENT
    end

    if approle_path_segment.nil?
      approle_path_segment = DEFAULT_APPROLE_PATH_SEGMENT
    end
    vault_base_uri = URI(vault_addr)
    # URI is used here to parse the vault_addr into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error, "Unable to parse a hostname from #{vault_addr}" unless vault_base_uri.hostname

    client = Puppet.runtime[:http]

    case auth_method
    when 'cert'
      token = get_cert_auth_token(client,
                                  vault_base_uri,
                                  cert_path_segment,
                                  cert_role,
                                  namespace)
    when 'approle'
      raise Puppet::Error, 'role_id and VAULT_ROLE_ID are both nil' if vault_role_id.nil?
      raise Puppet::Error, 'secret_id and VAULT_SECRET_ID are both nil' if vault_secret_id.nil?
      token = get_approle_auth_token(client,
                                     vault_base_uri,
                                     approle_path_segment,
                                     role_id,
                                     secret_id,
                                     namespace)
    end

    secret_uri = vault_base_uri + "/v1/#{path.delete_prefix('/')}"
    data = get_secret(client,
                      secret_uri,
                      token,
                      namespace,
                      field)
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end

  private

  def auth_login_body(cert_role)
    if cert_role
      { name: cert_role }.to_json
    else
      ''
    end
  end

  def get_secret(client, uri, token, namespace, key)
    headers = { 'X-Vault-Token' => token, 'X-Vault-Namespace' => namespace }.delete_if { |_key, value| value.nil? }
    secret_response = client.get(uri,
                                 headers: headers,
                                 options: { include_system_store: true })
    unless secret_response.success?
      message = "Received #{secret_response.code} response code from vault at #{uri} for secret lookup"
      raise Puppet::Error, append_api_errors(message, secret_response)
    end
    begin
      if key.nil?
        JSON.parse(secret_response.body)['data']
      else
        JSON.parse(secret_response.body)['data']['data'][key]
      end
    rescue StandardError
      raise Puppet::Error, 'Error parsing json secret data from vault response'
    end
  end

  def get_cert_auth_token(client, vault_addr, cert_path_segment, cert_role, namespace)
    role_data = auth_login_body(cert_role)
    segment = if cert_path_segment.end_with?('/')
                cert_path_segment
              else
                cert_path_segment + '/'
              end
    login_url = vault_addr + segment + 'login'
    get_token(client, login_url, role_data, namespace)
  end

  def get_approle_auth_token(client, vault_addr, path_segment, role_id, secret_id, namespace)
    vault_request_data = {
      role_id: role_id,
      secret_id: secret_id
    }.to_json

    login_url = vault_addr + path_segment + 'login'
    get_token(client, login_url, vault_request_data, namespace)
  end

  def get_token(client, login_url, request_data, namespace)
    headers = { 'Content-Type' => 'application/json', 'X-Vault-Namespace' => namespace }.delete_if { |_key, value| value.nil? }
    response = client.post(login_url,
                           request_data,
                           headers: headers,
                           options: { include_system_store: true })
    unless response.success?
      message = "Received #{response.code} response code from vault at #{login_url} for authentication"
      raise Puppet::Error, append_api_errors(message, response)
    end

    begin
      token = JSON.parse(response.body)['auth']['client_token']
    rescue StandardError
      raise Puppet::Error, 'Unable to parse client_token from vault response'
    end

    raise Puppet::Error, 'No client_token found' if token.nil?

    token
  end

  def append_api_errors(message, response)
    errors   = json_parse(response, 'errors')
    warnings = json_parse(response, 'warnings')
    message << " (api errors: #{errors})" if errors
    message << " (api warnings: #{warnings})" if warnings
    message
  end

  def json_parse(response, field)
    JSON.parse(response.body)[field]
  rescue StandardError
    nil
  end
end
