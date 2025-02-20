# frozen_string_literal: true

require 'spec_helper'

describe 'vault_lookup::unwrap' do
  let(:function) { subject }

  it 'converts sensitive Hash' do
    exp = { 'password' => 'p1ssw0rd' }
    expect(subject).to run.with_params(
      { 'password' => Puppet::Pops::Types::PSensitiveType::Sensitive.new('p1ssw0rd') }
    ).and_return(exp)
  end

  it 'does nothing with String type' do
    h = { 'foo' => 'bar', 'boo' => 'baz' }
    expect(subject).to run.with_params(
      { 'foo' => 'bar', 'boo' => 'baz' }
    ).and_return(h)
  end
end
