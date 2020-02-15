Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup_without_key do
    param 'String', :path
    optional_param 'Pattern[/(?i:\Ahttps?:\/\/.*\z)/]', :vault_url # Type aliases are not pluginsynced, so we can't use Stdlib::HTTPUrl and have this function work when Deferred.
  end

  dispatch :lookup_with_key do
    param 'String', :path
    param 'String', :key
    optional_param 'Pattern[/(?i:\Ahttps?:\/\/.*\z)/]', :vault_url
  end

  def lookup_with_key(path, key, vault_url = nil)
    data = lookup(path, vault_url)
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data[key])
  end

  def lookup_without_key(path, vault_url = nil)
    data = lookup(path, vault_url)
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end

  def lookup(path, vault_url)
    if vault_url.nil?
      Puppet.debug 'No Vault address was set on function, defaulting to value from VAULT_ADDR env value'
      vault_url = ENV['VAULT_ADDR']
      raise Puppet::Error, 'No vault_url given and VAULT_ADDR env variable not set' if vault_url.nil?
    end

    uri = URI(vault_url)
    # URI is used here to just parse the vault_url into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error, "Unable to parse a hostname from #{vault_url}" unless uri.hostname

    use_ssl = uri.scheme == 'https'
    connection = Puppet::Network::HttpPool.http_instance(uri.host, uri.port, use_ssl)

    token = get_auth_token(connection)

    secret_response = connection.get("/v1/#{path}", 'X-Vault-Token' => token)
    unless secret_response.is_a?(Net::HTTPOK)
      message = "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
      raise Puppet::Error, append_api_errors(message, secret_response)
    end

    begin
      JSON.parse(secret_response.body)['data']
    rescue StandardError
      raise Puppet::Error, 'Error parsing json secret data from vault response'
    end
  end

  private

  def get_auth_token(connection)
    response = connection.post('/v1/auth/cert/login', '')
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
