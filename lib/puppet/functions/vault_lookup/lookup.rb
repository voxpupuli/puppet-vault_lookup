Puppet::Functions.create_function(:'vault_lookup::lookup') do
  CERT_DELIMITERS = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
  CRL_DELIMITERS = /-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m
  EC_HEADER = /-----BEGIN EC PRIVATE KEY-----/

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
      # here we will duplicate code that puppet ssl_provider does, because it is private
      certname = Puppet[:certname]

      capem = Puppet::FileSystem.read(Puppet[:localcacert], encoding: 'UTF-8')
      cacerts = capem.scan(CERT_DELIMITERS).map do |text|
        OpenSSL::X509::Certificate.new(text)
      end

      crlpem = Puppet::FileSystem.read(Puppet[:hostcrl], encoding: 'UTF-8')
      crls = crlpem.scan(CRL_DELIMITERS).map do |text|
        OpenSSL::X509::CRL.new(text)
      end

      certpath = File.join(Puppet[:certdir], "#{certname.downcase}.pem")
      certpem = Puppet::FileSystem.read(certpath, encoding: 'UTF-8')
      client_cert = OpenSSL::X509::Certificate.new(certpem)

      keypath = File.join(Puppet[:privatekeydir], "#{certname.downcase}.pem")
      keypem = Puppet::FileSystem.read(keypath, encoding: 'UTF-8')
      if keypem =~ EC_HEADER
        private_key = OpenSSL::PKey::EC.new(keypem, nil)
      else
        private_key = OpenSSL::PKey::RSA.new(keypem, nil)
      end

      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CHECK_SS_SIGNATURE | OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL

      cacerts.each { |cert| store.add_cert(cert) }
      crls.each { |crl| store.add_crl(crl) }

      store_context = OpenSSL::X509::StoreContext.new(store, client_cert, [])
      store_context.verify

      ssl_context = Puppet::SSL::SSLContext.new(
        store: store, cacerts: cacerts, crls: crls,
        private_key: private_key, client_cert: client_cert, client_chain: store_context.chain,
        revocation: 'chain'
      ).freeze
    else
      ssl_context = nil
    end
    connection = Puppet::Network::HttpPool.connection(uri.host, uri.port, use_ssl: use_ssl, ssl_context:ssl_context)
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
