Puppet::Functions.create_function(:vault_lookup) do

  dispatch :vault_lookup do
    param 'String', :path
    param 'String', :vault_url
    optional_param 'Hash', :options
  end

  def vault_lookup(path, vault_url="http://vault.docker:8200", options = {})
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

    response = connection.post('/v1/auth/cert/logins',"")
    unless response.kind_of?(Net::HTTPOK)
      err_string = "Received #{response.code} response code from vault at #{uri.host} for authentication"
      Puppet.err(err_string)
      Puppet.debug("Errored response body: #{response.body}")
      raise Puppet::Error.new(err_string) if merged_options[:raise_exceptions] == true
      return default_options['default_return_value']
    end
    token = JSON.parse(response.body)['auth']['client_token']

    secret_response = connection.get("/v1/#{path}", {"X-Vault-Token" => token} )
    unless secret_response.kind_of?(Net::HTTPOK)
      err_string = "Received #{secret_response.code} response code from vault at #{uri.host} for secret lookup"
      Puppet.err(err_string)
      Puppet.debug("Errored response body: #{secret_response.body}")
      raise Puppet::Error.new(err_string) if merged_options[:raise_exceptions] == true
      return default_options['default_return_value']
    end
    data = JSON.parse(secret_response.body)['data']

    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end
end
