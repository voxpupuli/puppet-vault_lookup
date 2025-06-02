# frozen_string_literal: true

require 'spec_helper'
require 'mock_vault_helper'

include PuppetVaultLookupHelpers # rubocop:disable Style/MixinUsage
describe 'vault_lookup::lookup' do
  let(:function) { subject }

  it 'errors for malformed uri' do
    expect do
      function.execute('/v1/whatever', 'vault.docker')
    end.to raise_error(Puppet::Error, %r{Unable to parse a hostname})

    expect do
      function.execute('/v1/whatever', 'vault_addr' => 'vault.docker')
    end.to raise_error(Puppet::Error, %r{Unable to parse a hostname})
  end

  it 'errors when no vault_addr set and no VAULT_ADDR environment variable' do
    expect do
      function.execute('/v1/whatever')
    end.to raise_error(Puppet::Error, %r{No vault_addr given and VAULT_ADDR env variable not set})

    expect do
      function.execute('/v1/whatever', {})
    end.to raise_error(Puppet::Error, %r{No vault_addr given and VAULT_ADDR env variable not set})
  end

  it 'returns nil instead of raising when raising is disabled' do
    expect {
      result = function.execute('/v1/whatever', 'vault.docker', false)
      expect(result).to be(nil)
    }.not_to raise_error
  end

  it 'raises a Puppet error when auth fails' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthFailure)
    vault_server.start_vault do |port|
      expect do
        function.execute('thepath', "http://127.0.0.1:#{port}")
      end.to raise_error(Puppet::Error, %r{Received 403 response code from vault.*invalid certificate or no client certificate supplied})

      expect do
        function.execute('thepath', 'vault_addr' => "http://127.0.0.1:#{port}")
      end.to raise_error(Puppet::Error, %r{Received 403 response code from vault.*invalid certificate or no client certificate supplied})
    end
  end

  it 'raises a Puppet error when data lookup fails' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupDenied)
    vault_server.start_vault do |port|
      expect do
        function.execute('kv/test', "http://127.0.0.1:#{port}")
      end.to raise_error(Puppet::Error, %r{Received 403 response code from vault at .* for secret lookup.*permission denied})

      expect do
        function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}")
      end.to raise_error(Puppet::Error, %r{Received 403 response code from vault at .* for secret lookup.*permission denied})
    end
  end

  it 'raises a Puppet error when warning present' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupWarning)
    vault_server.start_vault do |port|
      expect do
        function.execute('kv/test', "http://127.0.0.1:#{port}")
      end.to raise_error(Puppet::Error, %r{Received 404 response code from vault at .* for secret lookup.*Invalid path for a versioned K/V secrets engine})

      expect do
        function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}")
      end.to raise_error(Puppet::Error, %r{Received 404 response code from vault at .* for secret lookup.*Invalid path for a versioned K/V secrets engine})
    end
  end

  it 'logs on, requests a kv1 secret using a token, and returns the data wrapped in the Sensitive type' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      result = function.execute('kv/test', "http://127.0.0.1:#{port}")
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')

      result_opts = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}")
      expect(result_opts).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result_opts.unwrap).to eq('foo' => 'bar')

      result_field = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'field' => 'foo')
      expect(result_field).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result_field.unwrap).to eq('bar')
    end
  end

  it 'logs on, requests a kv2 secret using a token, and returns the data wrapped in the Sensitive type' do
    custom_auth_segment = 'v1/custom/auth/segment'
    vault_server = MockVault.new
    vault_server.mount("/#{custom_auth_segment}/login", AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupSuccessKV2)
    vault_server.start_vault do |port|
      result = function.execute('kv/test', "http://127.0.0.1:#{port}", custom_auth_segment, '', '', 'bar')
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('baz')

      result_opts = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'cert_path_segment' => custom_auth_segment, 'field' => 'bar')
      expect(result_opts).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result_opts.unwrap).to eq('baz')

      result_no_field = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'cert_path_segment' => custom_auth_segment)
      expect(result_no_field).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result_no_field.unwrap).to eq('bar' => 'baz')
    end
  end

  it 'is successful when providing a cert_role while authenticating' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccessWithRole)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      result = function.execute('kv/test', "http://127.0.0.1:#{port}", nil, 'test-cert-role')
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')

      opts = {
        'vault_addr' => "http://127.0.0.1:#{port}",
        'cert_role' => 'test-cert-role'
      }
      result_opts = function.execute('kv/test', opts)
      expect(result_opts).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result_opts.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'is successful when providing a custom cert path segment without a trailing slash' do
    custom_auth_segment = 'v1/custom/auth/segment'
    vault_server = MockVault.new
    vault_server.mount("/#{custom_auth_segment}/login", AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      result = function.execute('kv/test', "http://127.0.0.1:#{port}", custom_auth_segment)
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')

      result_opts = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'cert_path_segment' => custom_auth_segment)
      expect(result_opts).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result_opts.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'logs on, requests a secret using a token, and returns the data wrapped in the Sensitive type from VAULT_ADDR' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      stub_const('ENV', ENV.to_hash.merge('VAULT_ADDR' => "http://127.0.0.1:#{port}"))
      result = function.execute('kv/test')
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'logs on on Vault with a namespace, requests a secret using a token, and returns the data wrapped in the Sensitive type' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccessWithNamespace)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      stub_const('ENV', ENV.to_hash.merge('VAULT_ADDR' => "http://127.0.0.1:#{port}"))
      stub_const('ENV', ENV.to_hash.merge('VAULT_NAMESPACE' => 'foo'))
      result = function.execute('kv/test')
      expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result.unwrap).to eq('foo' => 'bar')
    end
  end

  it 'caches the result when the same lookup is done more than once per catalog' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      allow(PuppetX::VaultLookup::Lookup).to receive(:get_secret).and_call_original.exactly(1).time
      result1 = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}")
      result2 = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}")
      result3 = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}")

      expect(result1).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result2).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result1.unwrap).to eq('foo' => 'bar')
      expect(result1.unwrap).to eq(result2.unwrap)
      expect(result1.unwrap).to eq(result3.unwrap)
    end
  end

  it 'builds the cache_key correctly' do
    vault_server = MockVault.new
    vault_server.mount('/v1/auth/cert/login', AuthSuccess)
    vault_server.mount('/v1/kv/test', SecretLookupSuccess)
    vault_server.start_vault do |port|
      allow(PuppetX::VaultLookup::Lookup).to receive(:get_secret).and_call_original.exactly(3).times
      result1 = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'namespace' => 'foo')
      result2 = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'namespace' => 'bar')
      result3 = function.execute('kv/test', 'vault_addr' => "http://127.0.0.1:#{port}", 'namespace' => 'baz')

      expect(result1).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result2).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
      expect(result1.unwrap).to eq('foo' => 'bar')
      expect(result1.unwrap).to eq(result2.unwrap)
      expect(result1.unwrap).to eq(result3.unwrap)
    end
  end

  context 'when using the agent auth method' do
    it 'a token header is not used' do
      vault_server = MockVault.new
      vault_server.mount('/v1/kv/test', SecretLookupSuccess)
      vault_server.start_vault do |port|
        stub_const('ENV', ENV.to_hash.merge('VAULT_ADDR' => "http://127.0.0.1:#{port}", 'VAULT_AUTH_METHOD' => 'agent'))
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_approle_auth_token).and_call_original
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_cert_auth_token).and_call_original
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_secret).with(hash_including(token: nil)).and_call_original
        result = function.execute('kv/test')

        expect(PuppetX::VaultLookup::Lookup).not_to have_received(:get_approle_auth_token)
        expect(PuppetX::VaultLookup::Lookup).not_to have_received(:get_cert_auth_token)
        expect(PuppetX::VaultLookup::Lookup).to have_received(:get_secret).with(hash_including(token: nil))
        expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
        expect(result.unwrap).to eq('foo' => 'bar')
      end
    end
  end

  context 'when using the agent_sing auth method' do
    let(:agent_sink_file) { '/tmp/vault_agent_sink' }

    it 'errors when token sink file does not exist' do
      vault_server = MockVault.new
      vault_server.mount('/v1/kv/test', SecretLookupSuccess)
      vault_server.start_vault do |port|
        stub_const('ENV', ENV.to_hash.merge(
                            'VAULT_ADDR' => "http://127.0.0.1:#{port}",
                            'VAULT_AUTH_METHOD' => 'agent_sink',
                            'VAULT_AGENT_SINK_FILE' => agent_sink_file
                          ))
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_approle_auth_token)
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_cert_auth_token)
        expect(PuppetX::VaultLookup::Lookup).not_to have_received(:get_approle_auth_token)
        expect(PuppetX::VaultLookup::Lookup).not_to have_received(:get_cert_auth_token)

        expect do
          function.execute('kv/test')
        end.to raise_error(Puppet::Error, %r{The agent_sink_file does not exist})
      end
    end

    it 'a token is read from the token sink' do
      vault_server = MockVault.new
      vault_server.mount('/v1/kv/test', SecretLookupSuccess)
      vault_server.start_vault do |port|
        stub_const('ENV', ENV.to_hash.merge(
                            'VAULT_ADDR' => "http://127.0.0.1:#{port}",
                            'VAULT_AUTH_METHOD' => 'agent_sink',
                            'VAULT_AGENT_SINK_FILE' => agent_sink_file
                          ))
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_approle_auth_token)
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_cert_auth_token)
        allow(PuppetX::VaultLookup::Lookup).to receive(:read_token_from_sink).with(sink: agent_sink_file).and_return('abcdefg')
        allow(PuppetX::VaultLookup::Lookup).to receive(:get_secret).with(hash_including(token: 'abcdefg')).and_call_original

        result = function.execute('kv/test')

        expect(PuppetX::VaultLookup::Lookup).not_to have_received(:get_approle_auth_token)
        expect(PuppetX::VaultLookup::Lookup).not_to have_received(:get_cert_auth_token)
        expect(PuppetX::VaultLookup::Lookup).to have_received(:read_token_from_sink).with(sink: agent_sink_file)
        expect(PuppetX::VaultLookup::Lookup).to have_received(:get_secret).with(hash_including(token: 'abcdefg'))

        expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
        expect(result.unwrap).to eq('foo' => 'bar')
      end
    end
  end
end
