# frozen_string_literal: true

require 'spec_helper'

describe 'vault_lookup::fmt' do
  context 'deferred array format' do
    it {
      exp = Puppet::Pops::Types::TypeFactory.deferred.create('sprintf', ['foo=%<bar>d', { 'bar' => 2 }])
      # This kind_of matcher requires https://github.com/puppetlabs/rspec-puppet/pull/24
      expect(subject).to run.with_params(
        'foo=%<bar>d', { 'bar' => 2 }
      ).and_return(kind_of(Puppet::Pops::Types::PuppetObject))

      expect(subject).to run.with_params(
        'foo=%<bar>d', { 'bar' => 2 }
      ).and_return(exp)
    }
  end
end
