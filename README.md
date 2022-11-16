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
2. [Setup - The basics of getting started with vault_lookup](#setup)
3. [Usage - Configuration options and additional functionality](#usage)

## Description

For users with a Puppet Enterprise 2019 or open source Puppet 6 infrastructure
wanting to leverage secrets from an existing [Hashicorp
Vault](https://www.vaultproject.io/) server. Used with Puppet 6's Deferred type,
this allows agents to retrieve secrets from Vault when a catalog is applied. In
this way, the secret data is not embedded in the catalog and the master never
sees it. See [this blog
post](https://puppet.com/blog/secret-agents-man-secrets-store-integrations-puppet-6)
for more information and other secret store integrations.

Authentication with Vault is achieved via Puppet certificates or by using the
Approle authentication method. See the Vault documentation for more information
on setting up finer grained access controls.

## Requirements

This is expected to be run using the `Deferred` type, which requires Puppet
6.0.0 or later, and of course [Vault](https://www.vaultproject.io/) to store the
data.

## Setup

### To set up Vault to use the Puppet Server CA cert:

The `vault::vault_lookup()` function can use the Puppet agent's certificates in
order to authenticate to the Vault server; this means that before any agents
contact a Vault server, you must configure the Vault server with the Puppet
Server's CA certificate, and Vault must be part of the same certificate
infrastructure.

1. Set up Vault using Puppet certs (if not already set up this way)
  If the Vault host has a Puppet agent on it then you can just use the existing
  certificates. Otherwise generate a new certificate with `puppetserver ca` and
  copy the files.

```
puppetserver ca generate --certname my-vault.my-domain.me
```

  In the Vault listener configuration, set `tls_client_ca_file` as the Puppet CA
  cert, `tls_cert_file` as the agent or generated certificate, and
  `tls_key_file` as the agent or generated private key.

2. Enable cert auth for Vault
  Hashicorp’s Vault supports a variety of auth methods that are listed in their
  documentation; the auth method required for usage with the
  `vault:vault_lookup()` function is named cert, and can be turned on with the
  Vault CLI:

```
$ vault auth enable cert
```
3. Upload the Puppet Server CA certificate to Vault.
  After cert auth has been enabled for Vault, upload the CA certificate from
  your Puppet Server to Vault and add it as a trusted certificate.

```
$ vault write auth/cert/certs/puppetserver \
    display_name=puppet \
    policies=prod,test \
    certificate=@/path/to/puppetserver/ca.pem \
    ttl=3600
```

Once the certificate has been uploaded, any Puppet agent with a signed
certificate will be able to authenticate with Vault.

### To use AppRole Authentication

`vault:vault_lookup()` can also use AppRole authentication to authenticate against Vault with a valid `role_id` and `secret_id`.  See [The Approle Vault Documentation](https://www.vaultproject.io/docs/auth/approle) for detailed explanations of creating and obtaining the security credentials.   You will need the Role ID (non sensitive) and the Secret ID (sensitive!).  The Secret ID can be provided as an argument to the `vault:vault_lookup()` function but it is recommended to pass this as an environment variable and not bake this into code.

Example:
```
# vault read auth/approle/role/puppet/role-id
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

In order to use the AppRole auth engine you must set the `VAULT_AUTH_METHOD` environment variable (defaults to cert) to `approle`

```
export VAULT_AUTH_METHOD=approle
export VAULT_ROLE_ID=XXXXX-XXXX-XXX-XX-XXXXXXXXXX
export VAULT_SECRET_ID=YYYYY-YYYY-YYY-YY-YYYYYYYYYYY
```



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

The lookup done by `vault::vault_lookup()` can be configured in two ways: positional arguments or with a hash of options.

In both cases, the path to the secret is the first positional argument and is required. All other arguments are optional.

Positional arguments signature:
```
vault::vault_lookup( <path>, [<vault_addr>], [<cert_path_segment>], [<cert_role>], [<namespace>], [<field>], [<auth_method>], [<role_id>], [<secret_id>], [<approle_path_segment>] )
```

Options hash signature:
```
vault::vault_lookup( <path>, [<options_hash>] )
```

Arguments in `[square brackets]` are optional.


Here are some examples of each method:
```
# Positional arguments
$data_1a = vault::vault_lookup('secret/db/password', 'https://vault.corp.net:8200')
$data_2a = vault::vault_lookup('secret/db/blah', 'https://vault.corp.net:8200', undef, undef, undef, undef, 'approle', 'team_a', 'abcd1234!@#')

# Options hash
$data_1b = vault::vault_lookup('secret/db/password', { 'vault_addr' => 'https://vault.corp.net:8200' })
$data_2b = vault::vault_lookup('secret/db/blah', {
  'vault_addr'  => 'https://vault.corp.net:8200',
  'auth_method' => 'approle',
  'role_id'     => 'team_a',
  'secret_id'   => 'abcd1234!@#',
})
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

