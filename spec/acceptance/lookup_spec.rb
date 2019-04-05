require 'beaker-rspec'
require 'beaker-rspec/spec_helper'
require 'beaker-puppet'
require 'beaker/puppet_install_helper'
require 'beaker/module_install_helper'

describe 'lookup with vault configured to accept certs from puppetserver' do
  before(:all) do
    # Since beaker has not run the PrebuiltSteps to add /opt/puppetlabs/* to the
    # PATH, add the directories to the top of the /etc/bash.bashrc so the dirs
    # are available for all non-interactive bash shells.
    on(master, "sed -i '1s_^_PATH=/opt/puppetlabs/server/bin:/opt/puppetlabs/puppet/bin:/opt/puppetlabs/bin:$PATH\\n_' /etc/bash.bashrc")
    install_module_on(master)
    vault = find_host_with_role('vault')
    scp_to(vault, 'spec/acceptance/fixtures/unseal.sh', '/root/unseal.sh')
    on(vault, 'su root /root/unseal.sh')

    step 'ensure the puppetserver is up and available' do
      opts = { desired_exit_codes: [0], max_retries: 60, retry_interval: 1 }
      retry_on(
        master,
        "/opt/puppetlabs/puppet/bin/curl --insecure --fail \"https://127.0.0.1:8140/production/status/test\" | grep -q '\"is_alive\":true'",
        opts,
      )
    end
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

  it 'retrieves a secret from vault during an agent run with an env value for vault' do
    scp_to(
      master,
      'spec/acceptance/fixtures/env_value/site.pp',
      '/etc/puppetlabs/code/environments/production/manifests',
    )
    response = on(master, 'VAULT_ADDR=https://vault.local:8200 /opt/puppetlabs/bin/puppet agent -t --server puppetserver.local', acceptable_exit_codes: [0, 2])
    assert_match(%r{Notice.+foo.+bar}, response.stdout)
  end
end
