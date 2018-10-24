require 'beaker-rspec'
require 'beaker-rspec/spec_helper'
require 'beaker-puppet'
require 'beaker/puppet_install_helper'
require 'beaker/module_install_helper'

describe 'lookup with vault configured to accept certs from puppetserver' do
  before(:all) do
    # install here doesn't really install, it just moves the module over to
    # the host machine; after install, the test needs to move it somewhere
    # on the module path.
    install_module_on(master)
    on(master, 'mv /vault_lookup /etc/puppetlabs/code/environments/production/modules')
    vault = find_host_with_role('vault')
    scp_to(vault, 'spec/acceptance/fixtures/unseal.sh', '/root/unseal.sh')
    on(vault, 'su root /root/unseal.sh')

    # Move the PKI infrastructure created on the vault container onto puppetserver
    tmpdir = Dir.mktmpdir
    scp_from(vault, '/root/ca/intermediate/private/intermediate.key.pem', tmpdir)
    scp_from(vault, '/vault/config/crlchain.pem', tmpdir)
    scp_from(vault, '/vault/config/certbundle.pem', tmpdir)
    scp_to(master, "#{tmpdir}/crlchain.pem", '/root/crlchain.pem')
    scp_to(master, "#{tmpdir}/intermediate.key.pem", '/root/intermediate.key.pem')
    scp_to(master, "#{tmpdir}/certbundle.pem", '/root/certbundle.pem')

    # Something fails here with the find and delete file type, and the ca/infra_serials
    # is often left behind or instantly regenerated after the delete; sleeping momentarily
    # and then trying to ensure it is deleted has been successful...
    on(master, 'find /etc/puppetlabs/puppet/ssl/ -type f -delete')
    sleep 3
    on(master, 'rm /etc/puppetlabs/puppet/ssl/ca/infra_serials', acceptable_exit_codes: [0, 1])

    on(master, '/opt/puppetlabs/bin/puppetserver ca import --cert-bundle /root/certbundle.pem --crl-chain /root/crlchain.pem --private-key /root/intermediate.key.pem')
    on(master, 'service puppetserver reload')
  end

  it 'retrieves a secret from vault during an agent run' do
    scp_to(
      master,
      'spec/acceptance/fixtures/site.pp',
      '/etc/puppetlabs/code/environments/production/manifests',
    )
    response = on(master, '/opt/puppetlabs/bin/puppet agent -t --server puppetserver.local', acceptable_exit_codes: [0, 2])
    assert_match(%r{Notice.+foo.+bar}, response.stdout)
  end
end
