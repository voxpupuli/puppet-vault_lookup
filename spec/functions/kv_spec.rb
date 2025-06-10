# frozen_string_literal: true

require 'spec_helper'

describe 'vault_lookup::kv' do
  context 'with server address' do
    it {
      exp = Puppet::Pops::Types::TypeFactory.deferred.create('vault_lookup::lookup', ['kv/data/secret', { 'vault_addr' => 'https://vault.example.com:8200' }])
      # This kind_of matcher requires https://github.com/puppetlabs/rspec-puppet/pull/24
      expect(subject).to run.with_params(
        'kv/data/secret'
      ).and_return(kind_of(Puppet::Pops::Types::PuppetObject))

      expect(subject).to run.with_params(
        'kv/data/secret', { 'vault_addr' => 'https://vault.example.com:8200' }
      ).and_return(exp)
    }
  end

  context 'with lookup key' do
    let(:hiera_data) { { 'vault_lookup::server' => 'https://vault:8200' } }

    it {
      exp = Puppet::Pops::Types::TypeFactory.deferred.create('vault_lookup::lookup', ['secret', {}])

      expect(subject).to run.with_params(
        'secret'
      ).and_return(exp)
    }
  end

  context 'with vault_addr key' do
    it {
      exp = Puppet::Pops::Types::TypeFactory.deferred.create('vault_lookup::lookup', ['secret', { 'vault_addr' => 'https://vault:8200' }])

      expect(subject).to run.with_params(
        'secret', { 'vault_addr' => 'https://vault:8200' }
      ).and_return(exp)
    }
  end

  context 'with field key' do
    it {
      exp = Puppet::Pops::Types::TypeFactory.deferred.create('vault_lookup::lookup', ['secret', { 'field' => 'password' }])

      expect(subject).to run.with_params(
        'secret', { 'field' => 'password' }
      ).and_return(exp)
    }
  end
end
