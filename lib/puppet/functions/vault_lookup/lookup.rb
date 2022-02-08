Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup do
    param 'String', :path
    optional_param 'String', :vault_url
    optional_param 'String', :vault_namespace
    optional_param 'String', :vault_cert_path
    optional_param 'String', :vault_cert_role
    optional_param 'String', :key_field
    optional_param 'String', :vault_app_role_path
    optional_param 'String', :vault_app_role_name
    optional_param 'String', :vault_role_id_path
  end

  def lookup(path,
             vault_url = nil,
             vault_namespace = nil,
             vault_cert_path = 'cert',
             vault_cert_role = nil,
             key_field = nil,
             vault_app_role_path = nil,
             vault_app_role_name = nil,
             vault_role_id_path = nil)
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

    connection = Puppet.runtime[:http]

    cert_token = get_cert_auth_token(connection, vault_url, vault_namespace, vault_cert_path, vault_cert_role)

    if vault_app_role_name.nil? || vault_app_role_name == ''
      vault_token = cert_token
    else
      if vault_app_role_path.nil? || vault_app_role_path == ''
        Puppet.debug 'vault_app_role_path was not set on function, defaulting to approle'
        vault_app_role_path = 'approle'
      end
      secret_id = get_secret_id(connection, vault_url, vault_namespace, cert_token, vault_app_role_path, vault_app_role_name)

      role_file_name_construct = if key_field.nil? || key_field == ''
                                   path.sub('/', '-')
                                 else
                                   path.sub('/', '-') + '-' + key_field
                                 end

      if vault_role_id_path.nil? || vault_role_id_path == ''
        role_file = '/etc/vault/roleids/' + role_file_name_construct
      elsif vault_role_id_path.start_with?('env:')
        env_role_id = vault_role_id_path.split(':')[-1]
      elsif vault_role_id_path.end_with?('/')
        role_file = "#{vault_role_id_path}#{role_file_name_construct}"
      else
        role_file = vault_role_id_path
      end

      if vault_role_id_path.start_with?('env:')
        role_id = ENV[env_role_id]
        role_token = get_role_auth_token(connection, vault_url, vault_namespace, vault_app_role_path, role_id, secret_id)
        vault_token = role_token
      elsif File.exist?(role_file)
        role_id = File.open(role_file).read
        role_token = get_role_auth_token(connection, vault_url, vault_namespace, vault_app_role_path, role_id.chomp, secret_id)
        vault_token = role_token
      else
        raise Puppet::Error, "Role file #{role_file} required for role_id does not exist"
      end

    end

    secret_response = if vault_namespace.nil? || vault_namespace == ''
                        connection.get(
                                        URI(vault_url + '/v1/' + path.to_s),
                                        options: { 'include_system_store' => true },
                                        headers: { 'X-Vault-Token' => vault_token },
                                      )
                      else
                        connection.get(
                                        URI(vault_url + '/v1/' + path.to_s),
                                        options: { 'include_system_store' => true },
                                        headers: { 'X-Vault-Token' => vault_token, 'X-Vault-Namespace' => vault_namespace },
                                      )
                      end

    unless secret_response.success?
      message = "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
      raise Puppet::Error, append_api_errors(message, secret_response)
    end

    begin
      jsondata = if path.include? '/data/'
                   JSON.parse(secret_response.body)['data']['data']
                 else
                   JSON.parse(secret_response.body)['data']
                 end
      data = if key_field.nil? || key_field == ''
               jsondata
             else
               JSON.parse(jsondata)[key_field]
             end
    rescue StandardError
      raise Puppet::Error, 'Error parsing json secret data from vault response'
    end

    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end

private

  def get_cert_auth_token(connection, vault_url, vault_namespace, vault_cert_path, vault_cert_role)
    role_data = if vault_cert_role.nil? || vault_cert_role == ''
                  ''
                else
                  "{\"name\": \"#{vault_cert_role}\"}"
                end
    
    response = if vault_namespace.nil? || vault_namespace == ''
                  connection.post(
                                  URI(vault_url + '/v1/auth/' + vault_cert_path.to_s + '/login'),
                                  role_data,
                                  headers: { 'Content-Type' => 'application/json' },
                                  options: { 'include_system_store' => true },
                                )
               else
                 connection.post(
                                  URI(vault_url + '/v1/auth/' + vault_cert_path.to_s + '/login'),
                                  role_data,
                                  headers: { 'Content-Type' => 'application/json', 'X-Vault-Namespace' => vault_namespace },
                                  options: { 'include_system_store' => true },
                                )
               end

    unless response.success?
      message = "Received #{response.code} response code from vault at #{connection.address} for authentication"
      raise Puppet::Error, append_api_errors(message, response)
    end

    begin
      cert_token = JSON.parse(response.body)['auth']['client_token']
    rescue StandardError
      raise Puppet::Error, 'Unable to parse client_token from vault response'
    end

    raise Puppet::Error, 'No client_token found' if cert_token.nil?

    cert_token
  end

  def get_secret_id(connection, vault_url, vault_namespace, token, vault_app_role_path, vault_app_role_name)
    role_data = '{"metadata": "{ \"tag\": \"pupppet\" }"}'
    response = if vault_namespace.nil? || vault_namespace == ''
                 connection.post(
                                  URI(vault_url + '/v1/auth/' + vault_app_role_path.to_s + '/role/' + vault_app_role_name.to_s + '/secret-id'),
                                  role_data,
                                  headers: { 'Content-Type' => 'application/json', 'X-Vault-Token' => token },
                                  options: { 'include_system_store' => true },
                                )
               else
                 connection.post(
                                  URI(vault_url + '/v1/auth/' + vault_app_role_path.to_s + '/role/' + vault_app_role_name.to_s + '/secret-id'),
                                  role_data,
                                  headers: { 'Content-Type' => 'application/json', 'X-Vault-Token' => token, 'X-Vault-Namespace' => vault_namespace },
                                  options: { 'include_system_store' => true },
                 )
               end

    unless response.success?
      message = "Received #{response.code} response code from vault at #{connection.address} for authentication"
      raise Puppet::Error, append_api_errors(message, response)
    end

    begin
      secret_id = JSON.parse(response.body)['data']['secret_id']
    rescue StandardError
      raise Puppet::Error, 'Unable to parse secret_id from vault response'
    end

    raise Puppet::Error, 'No secret_id found' if secret_id.nil?

    secret_id
  end

  def get_role_auth_token(connection, vault_url, vault_namespace, vault_app_role_path, role_id, secret_id)
    role_data = "{\"role_id\": \"#{role_id}\",\"secret_id\": \"#{secret_id}\"}"

    response = if vault_namespace.nil? || vault_namespace == ''
                 connection.post(
                   URI(vault_url + '/v1/auth/' + vault_app_role_path.to_s + '/login'),
                   role_data,
                   headers: { 'Content-Type' => 'application/json' },
                   options: { 'include_system_store' => true },
                 )
               else
                 connection.post(
                   URI(vault_url + '/v1/auth/' + vault_app_role_path.to_s + '/login'),
                   role_data,
                   headers: { 'Content-Type' => 'application/json', 'X-Vault-Namespace' => vault_namespace },
                   options: { 'include_system_store' => true },
                 )
               end

    unless response.success?
      message = "Received #{response.code} response code from vault at #{connection.address} for authentication"
      raise Puppet::Error, append_api_errors(message, response)
    end

    begin
      role_token = JSON.parse(response.body)['auth']['client_token']
    rescue StandardError
      raise Puppet::Error, 'Unable to parse client_token from vault response'
    end

    raise Puppet::Error, 'No client_token found' if role_token.nil?

    role_token
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
