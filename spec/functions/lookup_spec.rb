require 'spec_helper'
require 'mock_vault_helper'

include PuppetVaultLookupHelpers
describe 'vault_lookup::lookup' do
  let(:function) { subject }

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
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthFailure)
    vault_server.start_vault do |port|
      expect {
        function.execute('thepath', "http://127.0.0.1:#{port}")
      }.to raise_error(Puppet::Error, %r{Received 403 response code from vault.*invalid certificate or no client certificate supplied})
    end
  end

  it 'raises a Puppet error when data lookup fails' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/secret/test', SecretLookupDenied)
    vault_server.start_vault do |port|
      expect {
        function.execute('secret/test', "http://127.0.0.1:#{port}")
      }.to raise_error(Puppet::Error, %r{Received 403 response code from vault at .* for secret lookup.*permission denied})
    end
  end

  it 'raises a Puppet error when warning present' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/secret/test', SecretLookupWarning)
    vault_server.start_vault do |port|
      expect {
        function.execute('secret/test', "http://127.0.0.1:#{port}")
      }.to raise_error(Puppet::Error, %r{Received 404 response code from vault at .* for secret lookup.*Invalid path for a versioned K/V secrets engine})
    end
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/secret/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      result = function.execute('secret/test', "http://127.0.0.1:#{port}")
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'is successful when providing a cert_role while authenticating' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccessWithRole)
    vault_server.mount('/v1/secret/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      result = function.execute('secret/test', "http://127.0.0.1:#{port}", nil, 'test-cert-role')
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'is successful when providing a custom cert path segment without a trailing slash' do
    custom_auth_segment = 'v1/custom/auth/segment'
    vault_server = MockVault.new
    vault_server.mount("/#{custom_auth_segment}/login", AuthSuccess)
    vault_server.mount('/v1/secret/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      result = function.execute('secret/test', "http://127.0.0.1:#{port}", custom_auth_segment)
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type from VAULT_ADDR' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/secret/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      stub_const('ENV', ENV.to_hash.merge('VAULT_ADDR' => "http://127.0.0.1:#{port}"))
      result = function.execute('secret/test')
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')
    end
  end
end
