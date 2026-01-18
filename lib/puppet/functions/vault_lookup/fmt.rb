# frozen_string_literal: true

Puppet::Functions.create_function('vault_lookup::fmt') do
  # @summary Lazy format function
  # Will be evaluated on client side - not during catalog compile on server
  # @param format Ruby printf syntax
  # @param args arguments passed to sprintf function
  # @see https://idiosyncratic-ruby.com/49-what-the-format.html
  # @example
  #   vault::fmt("%<x>d + %<y>d = %<z>d", {'x' => 2, 'y' => 2, 'z' => 5})
  # won't work on Puppet 7
  dispatch :fmt do
    param 'String', :format
    param 'Hash', :args
    return_type 'Deferred'
  end

  def fmt(format, args)
    Puppet::Pops::Types::TypeFactory.deferred.create('sprintf', [format, call_function('vault_lookup::unpack', args)])
  end
end
