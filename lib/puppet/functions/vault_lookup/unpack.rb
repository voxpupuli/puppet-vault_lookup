# frozen_string_literal: true

Puppet::Functions.create_function('vault_lookup::unpack') do
  # @summary Unwrap values in a Hash
  # @param args Hash possibly with Sensitive data
  dispatch :unpack do
    param 'Hash', :args
    return_type 'Hash'
  end

  def unpack(args)
    args.transform_values do |value|
      if value.is_a?(Puppet::Pops::Types::PSensitiveType::Sensitive)
        call_function('unwrap', value)
      else
        value
      end
    end
  end
end
