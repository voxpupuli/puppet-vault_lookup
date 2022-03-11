require 'spec_helper'

describe 'vault_lookup::lookup' do
  let(:function) { subject }

  let(:auth_success_data) do
    <<~JSON
      {
        "request_id": "03d11bd4-b994-c432-150f-5703a75641d1",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": null,
        "wrap_info": null,
        "warnings": null,
        "auth": {
          "client_token": "7dad29d2-40af-038f-cf9c-0aeb616f8d20",
          "accessor": "fd0c3269-9642-25e5-cebe-27a732be53a0",
          "policies": [
            "default",
            "secret_reader"
          ],
          "token_policies": [
            "default",
            "secret_reader"
          ],
          "metadata": {
            "authority_key_id": "b7:da:18:2f:cc:09:18:5d:d0:c5:24:0a:0a:66:46:ba:0d:f0:ea:4a",
            "cert_name": "vault.docker",
            "common_name": "localhost",
            "serial_number": "5",
            "subject_key_id": "ea:00:c0:0b:2d:38:01:28:ba:16:1f:08:64:de:0a:7c:8f:b7:43:33"
          },
          "lease_duration": 604800,
          "renewable": true,
          "entity_id": "e1bc06c5-303e-eec7-bf58-2a74fae2ec3d"
        }
      }
    JSON
  end

  let(:auth_failure_data) do
    '{"errors":["invalid certificate or no client certificate supplied"]}'
  end

  let(:secret_success_data) do
    '{"request_id":"e394e8ef-78f3-ac85-fbeb-33f060e911d4","lease_id":"","renewable":false,"lease_duration":604800,"data":{"foo":"bar"},"wrap_info":null,"warnings":null,"auth":null}
'
  end

  let(:permission_denied_data) do
    '{"errors":["permission denied"]}'
  end

  let(:warnings_data) do
    # rubocop:disable Metrics/LineLength
    '{"request_id":"0971a3db-f77a-4b0f-224d-35ff3e05d23d","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":["Invalid path for a versioned K/V secrets engine. See the API docs for the appropriate API endpoints to use. If using the Vault CLI, use \'vault kv get\' for this operation."],"auth":null}'
    # rubocop:enable Metrics/LineLength
  end

  it 'errors for malformed uri' do
    expect {
      function.execute('/v1/whatever', 'vault.docker')
    }.to raise_error(Puppet::Error, %r{Unable to parse a hostname})
  end

  it 'errors when no vault_url set and no VAULT_ADDR environment variable' do
    expect {
      function.execute('/v1/whatever')
    }.to raise_error(Puppet::Error, %r{No vault_url given and VAULT_ADDR env variable not set})
  end

  it 'raises a Puppet error when auth fails' do
    response = Puppet::HTTP::Response.new(URI('https://vault.doesnotexist:8200/v1/auth/cert/login'), 403, auth_failure_data)
    allow(response).to receive(:body).and_return(auth_failure_data)

    allow(Puppet.runtime[:http]).to receive(:address).and_return('vault.doesnotexist')
    expect(Puppet.runtime[:http]).to receive(:post).with(
      URI('https://vault.doesnotexist:8200/v1/auth/cert/login'),
      '',
      hash_including(
        headers: hash_including('Content-Type' => 'application/json'),
        options: hash_including('include_system_store' => true),
      ),
    ).and_return(response)

    expect {
      function.execute('thepath', 'https://vault.doesnotexist:8200')
    }.to raise_error(Puppet::Error, %r{Received 403 response code from vault at vault.doesnotexist for authentication \(api errors: \["invalid certificate or no client certificate supplied"\]})
  end

  it 'raises a Puppet error when data lookup fails' do
    auth_response = Puppet::HTTP::Response.new(URI('https://vault.doesnotexist:8200/v1/auth/cert/login'), 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(Puppet.runtime[:http]).to receive(:post).with(
      URI('https://vault.doesnotexist:8200/v1/auth/cert/login'),
      '',
      hash_including(
        headers: hash_including('Content-Type' => 'application/json'),
        options: hash_including('include_system_store' => true),
      ),
    ).and_return(auth_response)

    secret_response = Puppet::HTTP::Response.new(URI('https://vault.doesnotexist:8200/v1/secret/test'), 403, permission_denied_data)
    allow(secret_response).to receive(:body).and_return(permission_denied_data)

    allow(Puppet.runtime[:http]).to receive(:address).and_return('vault.doesnotexist')
    expect(Puppet.runtime[:http]).to receive(:get).with(
      URI('https://vault.doesnotexist:8200/v1/secret/test'),
      hash_including(
        headers: hash_including('Content-Type' => 'application/json' , 'X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'),
        options: hash_including('include_system_store' => true),
      ),
    ).and_return(secret_response)

    expect {
      function.execute('secret/test', 'https://vault.doesnotexist:8200')
    }.to raise_error(Puppet::Error, %r{Received 403 response code from vault at vault.doesnotexist for secret lookup \(api errors: \[""permission denied"\]})
  end

  it 'raises a Puppet error when warning present' do
    connection = instance_double('Puppet::Network::HTTP::Connection', address: 'vault.doesnotexist')
    expect(Puppet::Network::HttpPool).to receive(:http_instance).and_return(connection)

    auth_response = Net::HTTPOK.new('1.1', 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(connection).to receive(:post).with('/v1/auth/cert/login', '').and_return(auth_response)

    secret_response = Net::HTTPNotFound.new('1.1', 404, warnings_data)
    allow(secret_response).to receive(:body).and_return(warnings_data)
    expect(connection)
      .to receive(:get)
      .with('/v1/secret/test', hash_including('X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'))
      .and_return(secret_response)

    expect {
      function.execute('secret/test', 'https://vault.doesnotexist:8200')
    }.to raise_error(Puppet::Error, %r{Received 404 response code from vault at vault.doesnotexist for secret lookup.*Invalid path for a versioned K/V secrets engine})
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type' do
    connection = instance_double('Puppet::Network::HTTP::Connection', address: 'vault.doesnotexist')
    expect(Puppet::Network::HttpPool).to receive(:http_instance).and_return(connection)

    auth_response = Net::HTTPOK.new('1.1', 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(connection).to receive(:post).with('/v1/auth/cert/login', '').and_return(auth_response)

    secret_response = Net::HTTPOK.new('1.1', 200, '')
    expect(secret_response).to receive(:body).and_return(secret_success_data)
    expect(connection)
      .to receive(:get)
      .with('/v1/secret/test', hash_including('X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'))
      .and_return(secret_response)

    result = function.execute('secret/test', 'https://vault.doesnotexist:8200')
    expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
    expect(result.unwrap).to eq('foo' => 'bar')
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type from VAULT_ADDR' do
    stub_const('ENV', ENV.to_hash.merge('VAULT_ADDR' => 'https://vaultenv.doesnotexist:8200'))

    connection = instance_double('Puppet::Network::HTTP::Connection', address: 'vaultenv.doesnotexist:8200')
    expect(Puppet::Network::HttpPool).to receive(:http_instance).with('vaultenv.doesnotexist', 8200, true).and_return(connection)

    auth_response = Net::HTTPOK.new('1.1', 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(connection).to receive(:post).with('/v1/auth/cert/login', '').and_return(auth_response)

    secret_response = Net::HTTPOK.new('1.1', 200, '')
    expect(secret_response).to receive(:body).and_return(secret_success_data)
    expect(connection)
      .to receive(:get)
      .with('/v1/secret/test', hash_including('X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'))
      .and_return(secret_response)

    result = function.execute('secret/test')
    expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
    expect(result.unwrap).to eq('foo' => 'bar')
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type from namespace' do
    connection = instance_double('Puppet::Network::HTTP::Connection', address: 'vault.doesnotexist')
    expect(Puppet::Network::HttpPool).to receive(:http_instance).and_return(connection)

    auth_response = Net::HTTPOK.new('1.1', 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(connection).to receive(:post).with('/v1/namespace/auth/cert/login', '').and_return(auth_response)

    secret_response = Net::HTTPOK.new('1.1', 200, '')
    expect(secret_response).to receive(:body).and_return(secret_success_data)
    expect(connection)
      .to receive(:get)
      .with('/v1/namespace/secret/test', hash_including('X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'))
      .and_return(secret_response)

    result = function.execute('secret/test', 'https://vault.doesnotexist:8200')
    expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
    expect(result.unwrap).to eq('foo' => 'bar')
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type from VAULT_ADDR with namespace VAULT_NAMESPACE' do
    stub_const('ENV', ENV.to_hash.merge('VAULT_ADDR' => 'https://vaultenv.doesnotexist:8200'))
    stub_const('ENV', ENV.to_hash.merge('VAULT_NAMESPACE' => 'envnamespace'))

    connection = instance_double('Puppet::Network::HTTP::Connection', address: 'vaultenv.doesnotexist:8200')
    expect(Puppet::Network::HttpPool).to receive(:http_instance).with('vaultenv.doesnotexist', 8200, true).and_return(connection)

    auth_response = Net::HTTPOK.new('1.1', 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(connection).to receive(:post).with('/v1/envnamespace/auth/cert/login', '').and_return(auth_response)

    secret_response = Net::HTTPOK.new('1.1', 200, '')
    expect(secret_response).to receive(:body).and_return(secret_success_data)
    expect(connection)
      .to receive(:get)
      .with('/v1/envnamespace/secret/test', hash_including('X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'))
      .and_return(secret_response)

    result = function.execute('secret/test')
    expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
    expect(result.unwrap).to eq('foo' => 'bar')
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type with cert path custompath' do
    connection = instance_double('Puppet::Network::HTTP::Connection', address: 'vault.doesnotexist')
    expect(Puppet::Network::HttpPool).to receive(:http_instance).and_return(connection)

    auth_response = Net::HTTPOK.new('1.1', 200, '')
    expect(auth_response).to receive(:body).and_return(auth_success_data)
    expect(connection).to receive(:post).with('/v1/auth/custompath/login', '').and_return(auth_response)

    secret_response = Net::HTTPOK.new('1.1', 200, '')
    expect(secret_response).to receive(:body).and_return(secret_success_data)
    expect(connection)
      .to receive(:get)
      .with('/v1/secret/test', hash_including('X-Vault-Token' => '7dad29d2-40af-038f-cf9c-0aeb616f8d20'))
      .and_return(secret_response)

    result = function.execute('secret/test', 'https://vault.doesnotexist:8200')
    expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
    expect(result.unwrap).to eq('foo' => 'bar')
  end
end
