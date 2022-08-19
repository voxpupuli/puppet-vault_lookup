require 'webrick'

module PuppetVaultLookupHelpers
  SECRETS_WARNING_DATA = <<~JSON
    {
    	"request_id": "0971a3db-f77a-4b0f-224d-35ff3e05d23d",
    	"lease_id": "",
    	"renewable": false,
    	"lease_duration": 0,
    	"data": null,
    	"wrap_info": null,
    	"warnings": ["Invalid path for a versioned K/V secrets engine. See the API docs for the appropriate API endpoints to use. If using the Vault CLI, use \'vault kv get\' for this operation."],
    	"auth": null
    }
  JSON
                         .freeze

  SECRET_SUCCESS_DATA = <<~JSON
    {
    	"request_id": "e394e8ef-78f3-ac85-fbeb-33f060e911d4",
    	"lease_id": "",
    	"renewable": false,
    	"lease_duration": 604800,
    	"data": {
    		"foo": "bar"
    	},
    	"wrap_info": null,
    	"warnings": null,
    	"auth": null
    }
    JSON
                        .freeze

  SECRET_SUCCESS_KV2_DATA = <<~JSON
    {
      "request_id": "36b0eadc-890b-1da7-b06d-36bda6a9d94d",
      "lease_id": "",
      "lease_duration": 0,
      "renewable": false,
      "data": {
        "data": {
          "bar": "baz"
        },
    "metadata": {
          "created_time": "2022-07-21T12:38:39.082211175Z",
          "custom_metadata": null,
          "deletion_time": "",
          "destroyed": false,
          "version": 1
        }
      },
      "warnings": null
    }
    JSON
                        .freeze

  AUTH_SUCCESS_DATA = <<~JSON
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
                      .freeze

  # rubocop:disable Style/MethodName
  class AuthSuccess < WEBrick::HTTPServlet::AbstractServlet
    def do_POST(_request, response)
      response.body = AUTH_SUCCESS_DATA
      response.status = 200
      response.content_type = 'application/json'
    end
  end

  class AuthSuccessWithRole < WEBrick::HTTPServlet::AbstractServlet
    def do_POST(request, response)
      if JSON.parse(request.body) == { 'name' => 'test-cert-role' }
        response.body = AUTH_SUCCESS_DATA
        response.status = 200
        response.content_type = 'application/json'
      else
        response.status = 403
      end
    end
  end

  class AuthSuccessWithNamespace < WEBrick::HTTPServlet::AbstractServlet
    def do_POST(request, response)
      if request.header['x-vault-namespace'] == ['foo']
        response.body = AUTH_SUCCESS_DATA
        response.status = 200
        response.content_type = 'application/json'
      else
        response.status = 403
      end
    end
  end

  class SecretLookupDenied < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(_request, response)
      response.body = '{"errors":["permission denied"]}'
      response.status = 403
      response.content_type = 'application/json'
    end
  end

  class SecretLookupSuccess < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(_request, response)
      response.body = SECRET_SUCCESS_DATA
      response.status = 200
      response.content_type = 'application/json'
    end
  end

  class SecretLookupSuccessKV2 < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(_request, response)
      response.body = SECRET_SUCCESS_KV2_DATA
      response.status = 200
      response.content_type = 'application/json'
    end
  end

  class SecretLookupWarning < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(_request, response)
      response.body = SECRETS_WARNING_DATA
      response.status = 404
      response.content_type = 'application/json'
    end
  end

  class AuthFailure < WEBrick::HTTPServlet::AbstractServlet
    def do_POST(_request, response)
      response.body = '{"errors":["invalid certificate or no client certificate supplied"]}'
      response.status = 403
      response.content_type = 'application/json'
    end
  end
  # rubocop:enable Style/MethodName

  class MockVault
    def initialize
      @https = WEBrick::HTTPServer.new(
        BindAddress: '127.0.0.1',
        Port: 0 # webrick will choose the first available port, and set it in the config
      )

      trap('INT') do
        @https.shutdown
      end
    end

    def mount(*args)
      @https.mount(*args)
    end

    def start_vault
      Thread.new do
        @https.start
      end
      begin
        yield @https.config[:Port]
      ensure
        @https.shutdown
      end
    end
  end
end
