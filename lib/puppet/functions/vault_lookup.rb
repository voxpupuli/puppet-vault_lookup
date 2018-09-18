Puppet::Functions.create_function(:vault_lookup) do

  dispatch :vault_lookup do
    param 'String', :path
  end

  # code the vault_url to the test config address for now,
  # eventually move this to be configurable from @@options
  def vault_lookup(path, vault_url="https://vault.docker:8200")
    uri = URI(vault_url)
    client = Puppet::Network::HttpPool.http_ssl_instance(uri.host,uri.port)
    response = client.post('/v1/auth/cert/login',"")
    token = JSON.parse(response.body)['auth']['client_token']
    secret_response = client.get("/v1/#{path}", {"X-Vault-Token" => token} )
    data = JSON.parse(secret_response.body)['data']
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
  end
end
