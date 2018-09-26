Puppet::Functions.create_function(:'vault_lookup::lookup') do

  dispatch :lookup do
    param 'String', :path
    param 'String', :vault_url
    optional_param 'Boolean', :raise_exceptions
  end

  def lookup(path, vault_url, raise_exceptions = true)
    _lookup(path, vault_url)
  rescue StandardError => e
    raise if raise_exceptions
    Puppet.err(e.message)
    nil
  end

  private

  def _lookup(path, vault_url)
    uri = URI(vault_url)
    # URI is used here to just parse the vault_url into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error, "Unable to parse a hostname from #{vault_url}" unless uri.hostname

    connection = Puppet::Network::HttpPool.http_ssl_instance(uri.host, uri.port)

    token = get_auth_token(connection)

    secret_response = connection.get("/v1/#{path}", 'X-Vault-Token' => token)
    unless secret_response.is_a?(Net::HTTPOK)
      raise Puppet::Error, "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
    end

    begin
      data = JSON.parse(secret_response.body)['data']
    rescue StandardError
      raise Puppet::Error, "Error parsing json secret data from vault response"
    end

    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end

  def get_auth_token(connection)
    response = connection.post('/v1/auth/cert/login', '')
    unless response.is_a?(Net::HTTPOK)
      raise Puppet::Error, "Received #{response.code} response code from vault at #{uri.host} for authentication"
    end

    begin
      token = JSON.parse(response.body)['auth']['client_token']
    rescue StandardError
      raise Puppet::Error, "Unable to parse client_token from vault response"
    end

    raise Puppet::Error, 'No client_token found' if token.nil?

    token
  end
end
