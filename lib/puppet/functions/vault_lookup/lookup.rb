Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup do
    param 'String', :path
    optional_param 'String', :vault_url
  end

  def lookup(path, vault_url = nil)
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
    if use_ssl
      certname = Puppet[:certname]
      provider = Puppet::X509::CertProvider.new

      cacerts = provider.load_cacerts(required: true)
      crls = provider.load_crls(required: true)
      client_cert = provider.load_client_cert(certname, required: true)
      private_key = provider.load_private_key(certname, required: true, password: nil)

      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CHECK_SS_SIGNATURE | OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL

      cacerts.each { |cert| store.add_cert(cert) }
      crls.each { |crl| store.add_crl(crl) }

      store_context = OpenSSL::X509::StoreContext.new(store, client_cert, [])
      chain = store_context.chain

      ssl_context = Puppet::SSL::SSLContext.new(
        store: store, cacerts: cacerts, crls: crls,
        private_key: private_key, client_cert: client_cert, client_chain: chain,
        revocation: 'chain'
      ).freeze
    else
      ssl_context = nil
    end
    connection = Puppet::Network::HttpPool.connection(uri.host, uri.port, use_ssl, ssl_context)

    token = get_auth_token(connection)

    secret_response = connection.get("/v1/#{path}", 'X-Vault-Token' => token)
    unless secret_response.is_a?(Net::HTTPOK)
      message = "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
      raise Puppet::Error, append_api_errors(message, secret_response)
    end

    begin
      data = JSON.parse(secret_response.body)['data']
    rescue StandardError
      raise Puppet::Error, 'Error parsing json secret data from vault response'
    end

    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
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
