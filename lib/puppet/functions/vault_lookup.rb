Puppet::Functions.create_function(:vault_lookup) do
  require 'vault'

  dispatch :vault_lookup do
    param 'String', :path
  end

  # code the vault_url to the test config address for now,
  # eventually move this to be configurable from @@options
  def vault_lookup(path, vault_url="https://vault.docker:8200")
    Vault.configure do |config|
      config.ssl_ca_cert = Puppet[:ssl_client_ca_auth] || Puppet[:localcacert]

      #Concatenate the ssl cert and priv key for the ssl_pem_contents configuration for the vault gem
      ssl_host = Puppet.lookup(:ssl_host)
      contents = ssl_host.certificate.to_s + ssl_host.key.to_s
      config.ssl_pem_contents = contents

      config.address = vault_url

    end
    # Use the configured certificates to acquire a token
    Vault.auth.tls
    secret = Vault.logical.read(path)
    Puppet::Pops::Types::PSensitiveType::Sensitive.new(secret.data)
  end
end
