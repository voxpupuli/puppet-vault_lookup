# frozen_string_literal: true

require 'puppet'

module PuppetX
  module VaultLookup
    # Internal class for looking up data from Vault.
    class Lookup
      def self.lookup(cache:,
                      path:,
                      vault_addr: nil,
                      cert_path_segment: nil,
                      cert_role: nil,
                      namespace: nil,
                      field: nil,
                      auth_method: nil,
                      role_id: nil,
                      secret_id: nil,
                      approle_path_segment: nil,
                      agent_sink_file: nil)

        if vault_addr.nil?
          Puppet.debug 'No Vault address was set on function, defaulting to value from VAULT_ADDR env value'
          vault_addr = ENV['VAULT_ADDR']
          raise Puppet::Error, 'No vault_addr given and VAULT_ADDR env variable not set' if vault_addr.nil?
        end

        if namespace.nil?
          Puppet.debug 'No Vault namespace was set on function, defaulting to value from VAULT_NAMESPACE env value'
          namespace = ENV['VAULT_NAMESPACE']
        end

        # Check the cache.
        # The path, vault_addr, and namepsace fields could result in a different
        # secret value, so use them for the cache key.
        cache_key = [path, vault_addr, namespace, field]
        cache_hash = cache.retrieve(self)
        prior_result = cache_hash[cache_key]
        unless prior_result.nil?
          Puppet.debug "Using cached result for #{path}: #{prior_result}"
          return prior_result
        end

        auth_method = ENV['VAULT_AUTH_METHOD'] || 'cert' if auth_method.nil?
        role_id = ENV['VAULT_ROLE_ID'] if role_id.nil?
        secret_id = ENV['VAULT_SECRET_ID'] if secret_id.nil?
        cert_path_segment = 'v1/auth/cert/' if cert_path_segment.nil?
        approle_path_segment = 'v1/auth/approle' if approle_path_segment.nil?

        vault_base_uri = URI(vault_addr)
        # URI is used here to parse the vault_addr into a host string
        # and port; it's possible to generate a URI::Generic when a scheme
        # is not defined, so double check here to make sure at least
        # host is defined.
        raise Puppet::Error, "Unable to parse a hostname from #{vault_addr}" unless vault_base_uri.hostname

        client = Puppet.runtime[:http]

        case auth_method
        when 'cert'
          token = get_cert_auth_token(client,
                                      vault_base_uri,
                                      cert_path_segment,
                                      cert_role,
                                      namespace)
        when 'approle'
          raise Puppet::Error, 'role_id and VAULT_ROLE_ID are both nil' if role_id.nil?
          raise Puppet::Error, 'secret_id and VAULT_SECRET_ID are both nil' if secret_id.nil?

          token = get_approle_auth_token(client,
                                         vault_base_uri,
                                         approle_path_segment,
                                         role_id,
                                         secret_id,
                                         namespace)
        when 'agent'
          # Setting the token to nil causes the 'X-Vault-Token' header to not be
          # added by this function when making requests to Vault. Instead, we're
          # relying on the local Vault agent's cache to add the token into the
          # headers of our request. This assumes that 'use_auto_auth_token = true'
          # is in the Vault agent's cache config.
          # @see https://developer.hashicorp.com/vault/docs/agent/caching#using-auto-auth-token
          token = nil
        when 'agent_sink'
          # This assumes the token is availble in a sink file populated by the Vault Agent.
          # @see https://developer.hashicorp.com/vault/docs/agent/autoauth/sinks/file
          if agent_sink_file.nil?
            Puppet.debug "No agent sink file was set on function, defaulting to VAULT_AGENT_SINK_FILE env var: #{ENV['VAULT_AGENT_SINK_FILE']}"
            agent_sink_file = ENV['VAULT_AGENT_SINK_FILE']
          end
          raise Puppet::Error, 'agent_sink_file must be defined when using the agent_sink auth method' if agent_sink_file.nil?

          token = read_token_from_sink(sink: agent_sink_file)
        end

        secret_uri = vault_base_uri + "/v1/#{path.delete_prefix('/')}"
        data = get_secret(client: client,
                          uri: secret_uri,
                          token: token,
                          namespace: namespace,
                          key: field)

        sensitive_data = Puppet::Pops::Types::PSensitiveType::Sensitive.new(data)
        Puppet.debug "Caching found data for #{path}"
        cache_hash[cache_key] = sensitive_data
        sensitive_data
      end

      def self.auth_login_body(cert_role)
        if cert_role
          { name: cert_role }.to_json
        else
          ''
        end
      end

      def self.get_secret(client:, uri:, token:, namespace:, key:)
        headers = { 'X-Vault-Token' => token, 'X-Vault-Namespace' => namespace }.delete_if { |_key, value| value.nil? }
        secret_response = client.get(uri,
                                     headers: headers,
                                     options: { include_system_store: true })
        unless secret_response.success?
          message = "Received #{secret_response.code} response code from vault at #{uri} for secret lookup"
          raise Puppet::Error, append_api_errors(message, secret_response)
        end
        begin
          json_data = JSON.parse(secret_response.body)
          if key.nil? && json_data['data'].key?('data')
            json_data['data']['data']
          elsif key.nil?
            json_data['data']
          elsif json_data['data'].key?('data')
            json_data['data']['data'][key]
          else
            json_data['data'][key]
          end
        rescue StandardError
          raise Puppet::Error, 'Error parsing json secret data from vault response'
        end
      end

      def self.get_cert_auth_token(client, vault_addr, cert_path_segment, cert_role, namespace)
        role_data = auth_login_body(cert_role)
        segment = if cert_path_segment.end_with?('/')
                    cert_path_segment
                  else
                    "#{cert_path_segment}/"
                  end
        login_url = vault_addr + segment + 'login' # rubocop:disable Style/StringConcatenation
        get_token(client, login_url, role_data, namespace)
      end

      def self.get_approle_auth_token(client, vault_addr, path_segment, role_id, secret_id, namespace)
        vault_request_data = {
          role_id: role_id,
          secret_id: secret_id
        }.to_json

        login_url = vault_addr + path_segment + 'login' # rubocop:disable Style/StringConcatenation
        get_token(client, login_url, vault_request_data, namespace)
      end

      def self.get_token(client, login_url, request_data, namespace)
        headers = { 'Content-Type' => 'application/json', 'X-Vault-Namespace' => namespace }.delete_if { |_key, value| value.nil? }
        response = client.post(login_url,
                               request_data,
                               headers: headers,
                               options: { include_system_store: true })
        unless response.success?
          message = "Received #{response.code} response code from vault at #{login_url} for authentication"
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

      def self.append_api_errors(message, response)
        errors   = json_parse(response, 'errors')
        warnings = json_parse(response, 'warnings')
        # Can't modify frozen String, so we copy.
        copy = message.dup
        copy << " (api errors: #{errors})" if errors
        copy << " (api warnings: #{warnings})" if warnings
        copy
      end

      def self.json_parse(response, field)
        JSON.parse(response.body)[field]
      rescue StandardError
        nil
      end

      def self.read_token_from_sink(sink:)
        raise Puppet::Error, "The agent_sink_file does not exist or is not readable: #{sink}" unless Puppet::FileSystem.exist?(sink)

        Puppet::FileSystem.read(sink).chomp
      end
    end
  end
end
