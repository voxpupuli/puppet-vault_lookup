# Changelog

All notable changes to this project will be documented in this file.
Each new release typically also includes the latest modulesync defaults.
These should not affect the functionality of the module.

## [v1.0.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v1.0.0) (2023-05-01)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.7.0...v1.0.0)

**Breaking changes:**

- Drop Puppet 6 support [\#81](https://github.com/voxpupuli/puppet-vault_lookup/pull/81) ([bastelfreak](https://github.com/bastelfreak))

**Implemented enhancements:**

- Allow field to be used with v1 data format [\#76](https://github.com/voxpupuli/puppet-vault_lookup/pull/76) ([treydock](https://github.com/treydock))

**Closed issues:**

- Agent unable to connect to Vault because of cert issue [\#62](https://github.com/voxpupuli/puppet-vault_lookup/issues/62)
- Detection of what kv version the vault is should be done via a different heuristic. [\#56](https://github.com/voxpupuli/puppet-vault_lookup/issues/56)

**Merged pull requests:**

- Move bulk of logic to PuppetX::VaultLookup::Lookup [\#77](https://github.com/voxpupuli/puppet-vault_lookup/pull/77) ([natemccurdy](https://github.com/natemccurdy))

## [v0.7.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.7.0) (2023-04-19)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.6.0...v0.7.0)

**Implemented enhancements:**

- Add new auth methods: agent, agent\_sink [\#66](https://github.com/voxpupuli/puppet-vault_lookup/pull/66) ([natemccurdy](https://github.com/natemccurdy))
- Cache the result of a lookup [\#65](https://github.com/voxpupuli/puppet-vault_lookup/pull/65) ([natemccurdy](https://github.com/natemccurdy))
- Allow for setting lookup options with a hash instead of positional arguments [\#64](https://github.com/voxpupuli/puppet-vault_lookup/pull/64) ([natemccurdy](https://github.com/natemccurdy))

**Closed issues:**

- Retreiving a field value fails. [\#69](https://github.com/voxpupuli/puppet-vault_lookup/issues/69)
- undefined local variable or method 'vault\_role\_id' [\#68](https://github.com/voxpupuli/puppet-vault_lookup/issues/68)
- \[Feature Request\] Ability not to do cert auth login as part of lookup [\#24](https://github.com/voxpupuli/puppet-vault_lookup/issues/24)
- Add local vault mode [\#7](https://github.com/voxpupuli/puppet-vault_lookup/issues/7)

**Merged pull requests:**

- README updates: more examples, explain auth methods [\#73](https://github.com/voxpupuli/puppet-vault_lookup/pull/73) ([natemccurdy](https://github.com/natemccurdy))
- Correction vault\_role\_id and vault\_secret\_id missing [\#67](https://github.com/voxpupuli/puppet-vault_lookup/pull/67) ([phaedriel](https://github.com/phaedriel))

## [v0.6.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.6.0) (2022-11-01)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.5.0...v0.6.0)

**Implemented enhancements:**

- Add AppRole Authentication  [\#59](https://github.com/voxpupuli/puppet-vault_lookup/pull/59) ([crayfishx](https://github.com/crayfishx))

## [v0.5.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.5.0) (2022-08-23)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.4.0...v0.5.0)

**Implemented enhancements:**

- Kv2 support with a specified secret key [\#54](https://github.com/voxpupuli/puppet-vault_lookup/pull/54) ([firstnevyn](https://github.com/firstnevyn))
- Feat: support retrieving secrets from non-puppet signed Vault listener [\#53](https://github.com/voxpupuli/puppet-vault_lookup/pull/53) ([firstnevyn](https://github.com/firstnevyn))

## [v0.4.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.4.0) (2022-06-30)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.3.0...v0.4.0)

**Implemented enhancements:**

- Add support for Vault Namespaces [\#29](https://github.com/voxpupuli/puppet-vault_lookup/pull/29) ([Augustin-FL](https://github.com/Augustin-FL))

## [v0.3.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.3.0) (2022-06-30)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.2.0...v0.3.0)

**Implemented enhancements:**

- Update function for work with Vault secured with Letsencrypt certificates [\#44](https://github.com/voxpupuli/puppet-vault_lookup/issues/44)
- \(MODULES-11321\) Use new Puppet http runtime; require Puppet 6.16 or newer [\#50](https://github.com/voxpupuli/puppet-vault_lookup/pull/50) ([tvpartytonight](https://github.com/tvpartytonight))

**Closed issues:**

- Error: Failed to apply catalog: undefined method `http\_ssl\_instance' for Puppet::Network::HttpPool:Module [\#39](https://github.com/voxpupuli/puppet-vault_lookup/issues/39)
- Getting the following puppet deprecation when reusing your code [\#22](https://github.com/voxpupuli/puppet-vault_lookup/issues/22)

## [v0.2.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.2.0) (2021-09-19)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.1.1...v0.2.0)

**Implemented enhancements:**

- Add Environmental Lookup option [\#10](https://github.com/voxpupuli/puppet-vault_lookup/pull/10) ([petems](https://github.com/petems))

**Fixed bugs:**

- append\_api\_errors wasn't returning message causing scrub on nil error [\#20](https://github.com/voxpupuli/puppet-vault_lookup/pull/20) ([qfire](https://github.com/qfire))

**Closed issues:**

- Allow Vault configuration from VAULT\_ADDR environment variable [\#8](https://github.com/voxpupuli/puppet-vault_lookup/issues/8)

**Merged pull requests:**

- delete unneeded fixtures file [\#37](https://github.com/voxpupuli/puppet-vault_lookup/pull/37) ([bastelfreak](https://github.com/bastelfreak))
- Adds warnings to error logging [\#23](https://github.com/voxpupuli/puppet-vault_lookup/pull/23) ([petems](https://github.com/petems))
- Fix acceptance failures [\#17](https://github.com/voxpupuli/puppet-vault_lookup/pull/17) ([tvpartytonight](https://github.com/tvpartytonight))
- Run acceptance tests in travis [\#11](https://github.com/voxpupuli/puppet-vault_lookup/pull/11) ([tvpartytonight](https://github.com/tvpartytonight))
- \(PUP-9212\) Add acceptance tests [\#6](https://github.com/voxpupuli/puppet-vault_lookup/pull/6) ([tvpartytonight](https://github.com/tvpartytonight))

## [v0.1.1](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.1.1) (2018-10-16)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/v0.1.0...v0.1.1)

**Merged pull requests:**

- Build with puppet 5 [\#4](https://github.com/voxpupuli/puppet-vault_lookup/pull/4) ([pcarlisle](https://github.com/pcarlisle))
- modulesync 2.0.0-24-g272899e [\#3](https://github.com/voxpupuli/puppet-vault_lookup/pull/3) ([pcarlisle](https://github.com/pcarlisle))

## [v0.1.0](https://github.com/voxpupuli/puppet-vault_lookup/tree/v0.1.0) (2018-10-10)

[Full Changelog](https://github.com/voxpupuli/puppet-vault_lookup/compare/102b16076768bfdcfbaf3f140aadc808c8e183f6...v0.1.0)

**Merged pull requests:**

- modulesync 2.1.0 [\#2](https://github.com/voxpupuli/puppet-vault_lookup/pull/2) ([pcarlisle](https://github.com/pcarlisle))
- README updates [\#1](https://github.com/voxpupuli/puppet-vault_lookup/pull/1) ([turbodog](https://github.com/turbodog))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
