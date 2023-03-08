# vault_lookup

[![Build Status](https://github.com/voxpupuli/puppet-vault_lookup/workflows/CI/badge.svg)](https://github.com/voxpupuli/puppet-vault_lookup/actions?query=workflow%3ACI)
[![Release](https://github.com/voxpupuli/puppet-vault_lookup/actions/workflows/release.yml/badge.svg)](https://github.com/voxpupuli/puppet-vault_lookup/actions/workflows/release.yml)
[![Puppet Forge](https://img.shields.io/puppetforge/v/puppet/vault_lookup.svg)](https://forge.puppetlabs.com/puppet/vault_lookup)
[![Puppet Forge - downloads](https://img.shields.io/puppetforge/dt/puppet/vault_lookup.svg)](https://forge.puppetlabs.com/puppet/vault_lookup)
[![Puppet Forge - endorsement](https://img.shields.io/puppetforge/e/puppet/vault_lookup.svg)](https://forge.puppetlabs.com/puppet/vault_lookup)
[![Puppet Forge - scores](https://img.shields.io/puppetforge/f/puppet/vault_lookup.svg)](https://forge.puppetlabs.com/puppet/vault_lookup)
[![puppetmodule.info docs](http://www.puppetmodule.info/images/badge.png)](http://www.puppetmodule.info/m/puppet-vault_lookup)
[![Apache-2 License](https://img.shields.io/github/license/voxpupuli/puppet-vault_lookup.svg)](LICENSE)

Module to integrate Puppet 6 (and newer) and Puppet Enterprise 2019 (and newer)
agents with Hashicorp Vault.

#### Table of Contents

1. [Description](#description)
2. [Requirements](#setup)
3. [Usage, Configuration, and Examples](#usage)
4. [Authentication Methods](#authentication-methods)

## Description

For Puppet 6+ or Puppet Enterprise 2019+ users wanting to use secrets from
[Hashicorp Vault](https://www.vaultproject.io/) on their Puppet agents, this
Puppet module provides the `vault_lookup::lookup()` function.

When used with Puppet 6's [`Deferred`
type](https://puppet.com/docs/puppet/7/deferring_functions.html), the function
allows agents to retrieve secrets from Vault when a catalog is applied rather
than compiled. In this way, the secret data is not embedded in the catalog and
the Puppetserver does not need permissions to read all your Vault secrets.


## Requirements

This modules assumes the following:
1. Puppet 6+
2. An existing [Vault](https://www.vaultproject.io/) infrastructure

The `vault_lookup::lookup()` function is expected to be run with the `Deferred`
type; as such, Puppet 6 or later is required.

And as this function is meant to read secrets from Vault, an existing Vault
infrastructure is assumed to be up and reachable by your Puppet agents.


## Usage

Install this module as you would in any other; the necessary code will
be distributed to Puppet agents via pluginsync.

In your manifests, call the `vault_lookup::lookup()` function using the
Deferred type. For example:

```puppet
$d = Deferred('vault_lookup::lookup', ["secret/test", 'https://vault.hostname:8200'])

node default {
  notify { example :
    message => $d
  }
}
```

The lookup function will be run on the agent and the value of `$d` will be
resolved when the catalog is applied. This will make a call to
`https://vault.hostname:8200/v1/secret/test` and wrap the result in Puppet's
`Sensitive` type, which prevents the value from being logged.

You can also choose not to specify the Vault URL, and then Puppet will use the
`VAULT_ADDR` environment variable. This will be either set on the command line, or
set in the service config file for Puppet, on Debian `/etc/default/puppet`, on RedHat
`/etc/sysconfig/puppet`:

```
$d = Deferred('vault_lookup::lookup', ["secret/test"])

node default {
  notify { example :
    message => $d
  }
}
```

### Configuring the Vault lookup

The lookup done by `vault_lookup::lookup()` can be configured in three ways:
positional arguments, a hash of options,  and/or environment variables.

In all cases, the path to the secret is the first positional argument and is
required. All other arguments are optional. Arguments in `[square brackets]`
below are optional.

#### Positional Arguments

```
vault_lookup::lookup( <path>, [<vault_addr>], [<cert_path_segment>], [<cert_role>], [<namespace>], [<field>], [<auth_method>], [<role_id>], [<secret_id>], [<approle_path_segment>], [<agent_sink_file>] )
```

#### Options Hash

```
vault_lookup::lookup( <path>, [<options_hash>] )
```

#### Environment Variables

Not all options can be set with environment variables. Use the table below to find the matching env var, if available. Also note that environment variables are only used if the option is not supplied to the function.

  | Option Name | Environment Variable |
  | ----------- | -------------------- |
  | `vault_addr`           | `VAULT_ADDR`            |
  | `cert_path_segment`    | ----                    |
  | `cert_role`            | ----                    |
  | `namespace`            | `VAULT_NAMESPACE`       |
  | `field`                | ----                    |
  | `auth_method`          | `VAULT_AUTH_METHOD`     |
  | `role_id`              | `VAULT_ROLE_ID`         |
  | `secret_id`            | `VAULT_SECRET_ID`       |
  | `approle_path_segment` | ----                    |
  | `agent_sink_file`      | `VAULT_AGENT_SINK_FILE` |


### Usage Examples

Here are some examples of each method:
```puppet
# Positional arguments

## Using the default 'cert' auth method.
$data_1a = vault_lookup::lookup('secret/db/password', 'https://vault.corp.net:8200')

## Using the 'approle' auth method.
$data_2a = vault_lookup::lookup('secret/db/blah', 'https://vault.corp.net:8200', undef, undef, undef, undef, 'approle', 'team_a', 'abcd1234!@#')

## Pulling out a specific field.
$password = vault_lookup::lookup('secret/test', 'http://vault.corp.net:8200', undef, undef, undef, 'password')
```

```puppet
# Options hash

## Using the default 'cert' auth method.
$data_1b = vault_lookup::lookup('secret/db/password', { 'vault_addr' => 'https://vault.corp.net:8200' })

## Using the 'approle' auth method.
$data_2b = vault_lookup::lookup('secret/db/blah', {
  'vault_addr'  => 'https://vault.corp.net:8200',
  'auth_method' => 'approle',
  'role_id'     => 'team_a',
  'secret_id'   => 'abcd1234!@#',
})

# Using 'field' to pull out a specific field from the data.
$password = vault_lookup::lookup('secret/test', {'vault_addr' => 'http://127.0.0.1:8200', 'field' => 'password'})

# Using Deferred is simpler with the options hash.
$password_deferred = Deferred('vault_lookup::lookup', ["secret/test", {
  vault_addr => 'http://127.0.0.1:8200',
  field      => 'password',
}])
```

### A note about caching

The `vault_lookup::lookup()` function caches the result of a lookup and will
use that cached result for the life of the catalog application (when using
`Deferred`) or catalog compilation (when not using `Deferred`).

Looked up values are cached based on a combination of their:
* Path in the Vault URI
* Vault Address
* Namespace

This means that you can call `vault_lookup::lookup()` multiple times for the
same piece of data or refer to the same `Deferred` value multiple times and
there will only be a single fetch from Vault. This helps to reduce the amount
of back-and-forth network traffic to your Vault cluster.

For example, in the code below, due to caching, the `secret/db/password` value
is only looked up once even though the function is called twice:

```puppet
# Wrap the function in Deferred, and save it to a variable.
#
# Since the path, vault_addr, and namespace don't change, only one Vault lookup
# will be made regardless of how many times the $db_password variable is used.
#
$db_password = Deferred('vault_lookup::lookup', [
  'secret/db/password',
  {'vault_addr' => 'https://vault.corp.net:8200'},
])

# Call the deferred function once.
file { '/etc/db.conf':
  ensure  => file,
  content => $db_password,
}

# Call the deferred function twice.
notify { 'show the DB password':
  message => $db_password,
}
```

But if the path, the Vault address, or the namespace change, a new lookup to
Vault will happen. For example, in the code below, even though the path is the
same in both of these lookups (`secret/db/password`), the namespace is
different, so a separate lookup will be made rather than the cached value from
the first lookup of `secret/db/password` being used.

```puppet
# Fetch a value from Vault without using a namespace.
$db_password = Deferred('vault_lookup::lookup', [
  'secret/db/password',
  {'vault_addr' => 'https://vault.corp.net:8200'},
])

# Fetch a value from Vault in the 'dev' namespace.
$db_password_namespaced = Deferred('vault_lookup::lookup', [
  'secret/db/password',
  {'vault_addr' => 'https://vault.corp.net:8200', 'namespace' => 'dev'},
])

file { '/etc/db.conf':
  ensure  => file,
  content => $db_password,
}

notify { 'show the dev namespace DB password':
  message => $db_password_namespaced,
}
```

## Authentication Methods

The `vault_lookup::lookup()` function can authenticate to Vault in a number of ways. This table shows the currently supported `auth_method` types:

| `auth_method` | Description |
| --- | --- |
|  `cert`       | (this is the default) Uses the Puppet agent's certificate via the [TLS Certificates](https://developer.hashicorp.com/vault/docs/auth/cert) auth method. |
|  `approle`    | Uses the [AppRole](https://developer.hashicorp.com/vault/docs/auth/approle) auth method. |
|  `agent`      | Uses a local Vault Agent's [auto-auth token](https://developer.hashicorp.com/vault/docs/agent/caching#using-auto-auth-token) and caching proxy. |
|  `agent_sink` | Uses a local Vault Agent's [auto-auth file sink](https://developer.hashicorp.com/vault/docs/agent/autoauth/sinks/file). |


### Puppetserver CA and agent certificates

The `vault_lookup::lookup()` function by default will use the Puppet agent's
certificates to authenticate to the Vault server. This means that before any
agents contact a Vault server, you must configure the Vault server with the
Puppet Server's CA certificate, and Vault must be part of the same certificate
infrastructure.

1. Set up Vault using Puppet certs (if not already set up this way). If the
   Vault host has a Puppet agent on it then you can just its existing host
   certificates. Otherwise generate a new certificate with `puppetserver ca`
   and copy the files.

   ```
   $ puppetserver ca generate --certname my-vault.my-domain.me
   ```

   In the Vault listener configuration, set `tls_client_ca_file` as the Puppet
   CA cert, `tls_cert_file` as the agent's or generated certificate, and
   `tls_key_file` as the agent's or generated private key.

2. Enable the `cert` auth backend in Vault.

   ```
   $ vault auth enable cert
   ```

3. Upload the Puppet Server CA certificate to Vault. After `cert` auth has been
   enabled for Vault, upload the CA certificate from your Puppet Server to
   Vault, and add it as a trusted certificate.

   ```
   $ vault write auth/cert/certs/puppetserver \
       display_name=puppet \
       policies=prod,test \
       certificate=@/path/to/puppetserver/ca.pem \
       ttl=3600
   ```


Once the certificate has been uploaded, any Puppet agent with a signed
certificate will be able to authenticate with Vault.

### AppRole

`vault:vault_lookup()` can also use AppRole authentication to authenticate
against Vault with a valid `role_id` and `secret_id`. See [The Approle Vault
Documentation](https://www.vaultproject.io/docs/auth/approle) for detailed
explanations of creating and obtaining the security credentials. You will need
the Role ID (non sensitive) and the Secret ID (sensitive!). The Secret ID can
be provided as an argument to the `vault:vault_lookup()` function but it is
recommended to pass this as an environment variable and not bake this into
code.

Example:
```
$ vault read auth/approle/role/puppet/role-id
Key        Value
---        -----
role_id    XXXXX-XXXX-XXX-XX-XXXXXXXXXX
```

```
# vault write -f auth/approle/role/puppet/secret-id
Key                   Value
---                   -----
secret_id             YYYYY-YYYY-YYY-YY-YYYYYYYYYYY
secret_id_accessor    ZZZZZ-ZZZZZZ-ZZZZZZ-ZZZZZZZZ-ZZZZ
secret_id_ttl         0s
```

In order to use the AppRole auth method, either set the `VAULT_AUTH_METHOD`
environment variable on the Puppet process to `approle` or set the
`auth_method` option to `approle` when calling the function:

```shell
export VAULT_AUTH_METHOD=approle
export VAULT_ROLE_ID=XXXXX-XXXX-XXX-XX-XXXXXXXXXX
export VAULT_SECRET_ID=YYYYY-YYYY-YYY-YY-YYYYYYYYYYY
```

### Vault Agent: auto-auth token

This method of authentication relies on a local Vault Agent running on the
Puppet agent host. The Vault Agent handles authenticating to your Vault server,
and the `vault_lookup::lookup()` function just needs to make requests through
the local Vault Agent's caching proxy. The Vault Agent in this scenario must be
using Auto Auth, have Caching enabled, and have `use_auto_auth_token` set to
`true`.

<https://developer.hashicorp.com/vault/docs/agent/caching#using-auto-auth-token>

An example Vault Agent config for this scenario is shown below:
```hcl
vault {
  address = "https://vault.corp.net:8200"
}

listener "tcp" {
  address = "127.0.0.1:8100"
  tls_disable = true
}

auto_auth {
  # Some type of auto_auth configuration from:
  # https://developer.hashicorp.com/vault/docs/agent/autoauth
}

cache {
  use_auto_auth_token = true
}
```

And here's how the `vault_lookup::lookup()` function can be used to talk to the
local Vault agent and use its token for authentication:
```puppet
# Talk to the local Vault Agent that has "use_auto_auth_token = true"
$data = Deferred('vault_lookup::lookup', ["secret/test", {
  vault_addr  => 'http://127.0.0.1:8200',
  auth_method => 'agent',
  field       => 'password',
}])

file { '/tmp/secret_data.txt':
  ensure  => file,
  owner   => 'app',
  group   => 'app',
  mode    => '0440',
  content => $data,
}
```

A benefit of this method is that is uses the Vault Agent's cached token rather
than generating a new token for each call of the function. This reduces the
load on your Vault servers as token generation can be an expensive operation.

### Vault Agent: auto-auth file sink

This method of authentication relies on a local Vault Agent running on the
Puppet agent host. The Vault Agent handles authenticating to your Vault server,
and the `vault_lookup::lookup()` function reads the cached token from a sink
file managed by the Vault Agent. Optionally, the lookup could also talk through
your Vault Agent's caching proxy if enabled.

The Vault Agent in this scenario must be using Auto Auth and an **unencrypted, non-response-wrapped** File Sink for the token.

<https://developer.hashicorp.com/vault/docs/agent/autoauth/sinks/file>

An example Vault Agent config for this scenario is shown below:
```hcl
vault {
  address = "https://vault.corp.net:8200"
}

# The listener is optional here, but could be used for the 'vault_addr' in
# the vault_lookup::lookup() Puppet function.
listener "tcp" {
  address     = "127.0.0.1:8100"
  tls_disable = true
}

auto_auth {
  # Some type of auto_auth method from:
  # https://developer.hashicorp.com/vault/docs/agent/autoauth/methods
  method { }

  sink {
    type = "file"
    config = {
      path = "/path/to/vault-token
    }
  }
}
```

And here's how the `vault_lookup::lookup()` function can be configured to use
the token from the auto-auth file sink for authentication:
```puppet
# Use the token from the local Vault Agent's auto-auth file sink.
$data = Deferred('vault_lookup::lookup', ["secret/test", {
  # This doesn't have to be the local Vault agent's proxy, but using it can
  # provide additional caching.
  vault_addr      => 'http://127.0.0.1:8200',
  auth_method     => 'agent_sink',
  agent_sink_file => '/path/to/vault-token',
  field           => 'password',
}])

file { '/tmp/secret_data.txt':
  ensure  => file,
  owner   => 'app',
  group   => 'app',
  mode    => '0440',
  content => $data,
}
```

A benefit of this method is that is uses the Vault Agent's cached token rather
than generating a new token for each call of the function. This reduces the
load on your Vault servers as token generation can be an expensive operation.

