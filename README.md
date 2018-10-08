
# vault_lookup

Module to communicate with Hashicorp Vault servers from a puppet agent.

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with vault_lookup](#setup)
3. [Usage - Configuration options and additional functionality](#usage)

## Description

For users with a puppet infrastructure looking to incorporate secret storage
with an existing [Hashicorp Vault](https://www.vaultproject.io/) server. Used
with Puppet 6's Deferred type, this allows agents to retrieve secrets from vault
when a catalog is applied. The secret data is not embedded in the catalog and
the master never sees it. Authentication is via puppet certificates. See the
vault documentation for more information on setting up fine grained access
controls.

## Requirements

This is expected to be run using the Deferred type, which requires Puppet 6.0.0,
and of course [Vault](https://www.vaultproject.io/) to store the data.

## Setup

The vault_lookup function uses the puppet agent's certificates in order to
authenticate to the vault server; this means that before any agents contact a
vault server, you must configure the vault server with the puppetserver's CA
certificate, and vault must be part of the same certificate infrastructure.

To set up vault to use the puppetserver CA cert:

1. Set up vault using puppet certs (if not already set up this way)
  If the vault host has a puppet agent you can just use the existing
  certificates. Otherwise generate a new certificate with `puppetserver ca` and
  copy the files.
 
```
puppetserver ca generate --certname my-vault.my-domain.me
```

  In the vault listener configuration, set `tls_client_ca_file` as the puppet ca
  cert, `tls_cert_file` as the agent or generated certificate, and
  `tls_key_file` as the agent or generated private key.

2. Enable cert auth for vault
  Hashicorp’s vault supports a variety of auth methods that are listed in their
  documentation; the auth method required for usage with the vault_lookup
  function is named cert, and can be turned on with the vault CLI:

```
$ vault auth enable cert
```
3. Upload the Puppet Server CA certificate to vault
  After cert auth has been enabled for vault, you can upload your the CA
  certificate from your Puppet Server to Vault and add it as a trusted
  certificate.

```
$ vault write auth/cert/certs/puppetserver \
    display_name=puppet \
    policies=prod,test \
    certificate=@/path/to/puppetserver/ca.pem \
    ttl=3600
```

Once the certificate has been uploaded, any puppet agent with a signed
certificate will be able to authenticate with vault.

## Usage

Install this module on your puppetserver installation; the necessary code will
distributed to puppet agents via pluginsync.

In your manifests, call the `vault_lookup::lookup` function using the Deferred
type. For example:

```puppet
$d = Deferred('vault_lookup::lookup', ["secret/test", 'https://vault.docker:8200'])

node default {
  notify { example :
    message => $d
  }
}
```

The lookup function will be run on the agent and the value of `$d` will be
resolved when the catalog is applied. This will make a call to
`https://vault.docker:8200/v1/secret/test` and wrap the result in Puppet's
`Sensitive` type, which prevents the value from being logged.
