Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup do
    param 'String', :path
    optional_param 'String', :vault_url
    optional_param 'Optional[String]', :vault_cert_path_segment
    optional_param 'String', :vault_cert_role
    optional_param 'String', :vault_namespace
    return_type 'Sensitive'
  end

  DEFAULT_CERT_PATH_SEGMENT = 'v1/auth/cert/'.freeze

  def lookup(path,
             vault_url = nil,
             vault_cert_path_segment = nil,
             vault_cert_role = nil,
             vault_namespace = nil)
    if vault_url.nil?
      Puppet.debug 'No Vault address was set on function, defaulting to value from VAULT_ADDR env value'
      vault_url = ENV['VAULT_ADDR']
      raise Puppet::Error, 'No vault_url given and VAULT_ADDR env variable not set' if vault_url.nil?
    end
    if vault_namespace.nil?
      Puppet.debug 'No Vault namespace was set on function, defaulting to value from VAULT_NAMESPACE env value'
      vault_namespace = ENV['VAULT_NAMESPACE']
    end

    if vault_cert_path_segment.nil?
      vault_cert_path_segment = DEFAULT_CERT_PATH_SEGMENT
    end

    vault_base_uri = URI(vault_url)
    # URI is used here to parse the vault_url into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error, "Unable to parse a hostname from #{vault_url}" unless vault_base_uri.hostname

    client = Puppet.runtime[:http]
    token = get_cert_auth_token(client,
                                vault_base_uri,
                                vault_cert_path_segment,
                                vault_cert_role,
                                vault_namespace)

    secret_uri = vault_base_uri + "/v1/#{path.delete_prefix('/')}"
    data = get_secret(client, secret_uri, token, vault_namespace)
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end

  private

  def auth_login_body(vault_cert_role)
    if vault_cert_role
      { name: vault_cert_role }.to_json
    else
      ''
    end
  end

  def get_secret(client, uri, token, namespace)
    headers = { 'X-Vault-Token' => token, 'X-Vault-Namespace' => namespace }.delete_if { |_key, value| value.nil? }
    secret_response = client.get(uri, headers: headers)
    unless secret_response.success?
      message = "Received #{secret_response.code} response code from vault at #{uri} for secret lookup"
      raise Puppet::Error, append_api_errors(message, secret_response)
    end
    begin
      JSON.parse(secret_response.body)['data']
    rescue StandardError
      raise Puppet::Error, 'Error parsing json secret data from vault response'
    end
  end

  def get_cert_auth_token(client, vault_url, vault_cert_path_segment, vault_cert_role, vault_namespace)
    role_data = auth_login_body(vault_cert_role)
    headers = { 'Content-Type' => 'application/json', 'X-Vault-Namespace' => vault_namespace }.delete_if { |_key, value| value.nil? }
    segment = if vault_cert_path_segment.end_with?('/')
                vault_cert_path_segment
              else
                vault_cert_path_segment + '/'
              end
    login_url = vault_url + segment + 'login'
    response = client.post(login_url,
                           role_data,
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
