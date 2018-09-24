Puppet::Functions.create_function(:vault_lookup) do

  dispatch :vault_lookup do
    param 'String', :path
    param 'String', :vault_url
    optional_param 'Hash', :options
  end

  def vault_lookup(path, vault_url, options = {})
    default_options = { 'raise_exceptions' => true,
                        'default_return_value' => 'vault_lookup_failure'
                      }

    merged_options = default_options.merge(options)
    uri = URI(vault_url)
    # URI is used here to just parse the vault_url into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error.new("Unable to parse a hostname from #{vault_url}") unless uri.hostname

    connection = Puppet::Network::HttpPool.http_ssl_instance(uri.host,uri.port)

    response = connection.post('/v1/auth/cert/login',"")
    unless response.kind_of?(Net::HTTPOK)
      err_string = "Received #{response.code} response code from vault at #{uri.host} for authentication"
      Puppet.err(err_string)
      raise Puppet::Error.new(err_string) if merged_options[:raise_exceptions] == true
      return default_options['default_return_value']
    end

    begin
      token = JSON.parse(response.body)['auth']['client_token']
      raise Puppet::Error('No client_token found') if token == nil
    rescue StandardError => e
      err_string = "Unable to parse client_token from vault response, original exception from #{e.class} and message: #{e.message}"
      Puppet.err(err_string)
      raise Puppet::Error.new(err_string) if merged_options[:raise_exceptions] == true
      return default_options['default_return_value']
    end

    secret_response = connection.get("/v1/#{path}", {"X-Vault-Token" => token} )
    unless secret_response.kind_of?(Net::HTTPOK)
      err_string = "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
      Puppet.err(err_string)
      raise Puppet::Error.new(err_string) if merged_options[:raise_exceptions] == true
      return default_options['default_return_value']
    end

    begin
      data = JSON.parse(secret_response.body)['data']
      raise Puppet::Error('No data found for given secret') if data == nil
    rescue StandardError => e
      err_string = "Unable to parse secret data from vault response, original exception from #{e.class} and message: #{e.message}"
      Puppet.err(err_string)
      raise Puppet::Error.new(err_string) if merged_options[:raise_exceptions] == true
      return default_options['default_return_value']
    end

    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end
end
