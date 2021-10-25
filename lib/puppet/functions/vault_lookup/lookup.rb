require 'puppet'
require 'puppet/util'
require 'yaml'
require 'fileutils'
require 'net/http'

Puppet::Functions.create_function(:'vault_lookup::lookup') do
  dispatch :lookup do
    param 'String', :path
    optional_param 'String', :vault_url
  end

  configfile = File.join([File.dirname(Puppet.settings[:config]),
                          'vault-lookup.yaml'])

  AUTH_METHOD = 'cert'
  VAULT_ADDR = ENV['VAULT_ADDR']
  VAULT_ROLE_ID = ''
  VAULT_SECRET_ID = ''

  if File.exist?(configfile)
    config = YAML.load_file(configfile)
    AUTH_METHOD = config['AUTH_METHOD'] if config.key?('AUTH_METHOD')
    VAULT_ADDR = config['VAULT_ADDR'] if config.key?('VAULT_ADDR')
    VAULT_ROLE_ID = config['VAULT_ROLE_ID'] if config.key?('VAULT_ROLE_ID')
    VAULT_SECRET_ID = config['VAULT_SECRET_ID'] if config.key?('VAULT_SECRET_ID')
  else
    Puppet.debug "Configuration file #{configfile} not found, using defaults"
  end

  unless ['cert', 'approle'].include?(AUTH_METHOD)
    raise(Puppet::Error, "vault_lookup auth method #{AUTH_METHOD} not supported, use one of cert or approle")
  end

  def lookup(path, vault_url = nil)
    if vault_url.nil?
      Puppet.debug 'No Vault address was set on function, defaulting to value from VAULT_ADDR env value or config file'
      vault_url = VAULT_ADDR
      raise Puppet::Error, 'No vault_url given and VAULT_ADDR not provided' if vault_url.nil?
    end

    uri = URI(vault_url)
    # URI is used here to just parse the vault_url into a host string
    # and port; it's possible to generate a URI::Generic when a scheme
    # is not defined, so double check here to make sure at least
    # host is defined.
    raise Puppet::Error, "Unable to parse a hostname from #{vault_url}" unless uri.hostname

    use_ssl = uri.scheme == 'https'

    if AUTH_METHOD == 'cert'
      connection = Puppet::Network::HttpPool.http_instance(uri.host, uri.port, use_ssl)
    elsif AUTH_METHOD == 'approle'
      # When using approle, Vault server certificate doesn't have to match
      # puppet CA, so we use a plain Net::HTTP connection here
      connection = Net::HTTP.start(uri.host, uri.port, :use_ssl => use_ssl)
    end

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
    if AUTH_METHOD == 'cert'
      response = connection.post('/v1/auth/cert/login', '')
    elsif AUTH_METHOD == 'approle'
      response = connection.post(
        '/v1/auth/approle/login',
        {
          'role_id'   => VAULT_ROLE_ID,
          'secret_id' => VAULT_SECRET_ID
        }.to_json,
        'Content-Type' => 'application/json',
      )
    else
      raise Puppet::Error, 'Vault auth method not supported'
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
