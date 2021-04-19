Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup do
    param 'String', :path
    optional_param 'String', :vault_url
    optional_param 'String', :vault_namespace
    optional_param 'String', :vault_cert_path
    optional_param 'String', :vault_role
    optional_param 'String', :key_field
  end

  def lookup(path, vault_url = nil, vault_namespace = nil, vault_cert_path = 'cert', vault_role = nil, key_field = nil)
    if vault_url.nil? || vault_url == ''
      Puppet.debug 'No Vault address was set on function, defaulting to value from VAULT_ADDR env value'
      vault_url = ENV['VAULT_ADDR']
      raise Puppet::Error, 'No vault_url given and VAULT_ADDR env variable not set' if vault_url.nil?
    end

    if vault_namespace.nil? || vault_namespace == ''
      Puppet.debug 'No Vault namespace was set on function, defaulting to value from VAULT_Namespace env value'
      vault_namespace = ENV['VAULT_NAMESPACE']
      if vault_namespace.nil? || vault_namespace == ''
        Puppet.debug 'No Vault namespace was set in Environment Variable, defaulting to value to root'
      end
    end

    if vault_cert_path.nil? || vault_cert_path == ''
      Puppet.debug 'No Vault_cert_path was set on function, defaulting to cert'
      vault_cert_path = 'cert'
    end
    uri = URI(vault_url)
    # URI is used here to just parse the vault_url into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error, "Unable to parse a hostname from #{vault_url}" unless uri.hostname

    use_ssl = uri.scheme == 'https'
    connection = Puppet::Network::HttpPool.http_instance(uri.host, uri.port, use_ssl)

    token = get_auth_token(connection, vault_namespace, vault_cert_path, vault_role)

    secret_response = if vault_namespace.nil? || vault_namespace == ''
                        connection.get("/v1/#{path}", 'X-Vault-Token' => token)
                      else
                        connection.get(
                          "/v1/#{path}",
                          {
                            'X-Vault-Token' => token,
                            'X-Vault-Namespace' => vault_namespace
                          }.to_json,
                        )
                      end

    unless secret_response.is_a?(Net::HTTPOK)
      message = "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
      raise Puppet::Error, append_api_errors(message, secret_response)
    end

    begin
      kvdata = if path.include? '/data/'
                 JSON.parse(secret_response.body)['data']['data']
               else
                 JSON.parse(secret_response.body)['data']
               end
      data = if key_field.nil? || key_field == ''
               kvdata
             else
               JSON.parse(kvdata)[key_field.to_s]
             end
    rescue StandardError
      raise Puppet::Error, 'Error parsing json secret data from vault response'
    end

    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end

  private

  def get_auth_token(connection, vault_namespace, vault_cert_path, vault_role)
    role_data = if vault_role.nil? || vault_role == ''
                  ''
                else
                  "{\"name\": \"#{vault_role}\"}"
                end
    response = if vault_namespace.nil? || vault_namespace == ''
                 connection.post("/v1/auth/#{vault_cert_path}/login", role_data)
               else
                 connection.post("/v1/auth/#{vault_cert_path}/login", role_data, 'X-Vault-Namespace' => vault_namespace)
               end

    unless response.is_a?(Net::HTTPOK)
      message = "Received #{response.code} response code from vault at #{connection.address} for authentication"
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
    errors = begin
               JSON.parse(response.body)['errors']
             rescue StandardError
               nil
             end
    warnings = begin
                 JSON.parse(response.body)['warnings']
               rescue StandardError
                 nil
               end
    message << " (api errors: #{warnings})" if warnings
    message << " (api errors: #{errors})" if errors
  end
end
