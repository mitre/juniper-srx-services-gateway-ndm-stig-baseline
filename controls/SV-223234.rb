control 'SV-223234' do
  title 'The Juniper SRX Services Gateway must limit the number of sessions per minute to an organization-defined number for SSH to protect remote access management from unauthorized access.'
  desc "The rate-limit command limits the number of SSH session attempts allowed per minute which helps limit an attacker's ability to perform DoS attacks. The rate limit should be as restrictive as operationally practical.

Juniper Networks recommends a best practice of 4 for the rate limit, however the limit should be as restrictive as operationally practical. 

User connections that exceed the rate-limit will be closed immediately after the connection is initiated. They will not be in a waiting state."
  desc 'check', 'Verify the Juniper SRX sets a connection-limit for the SSH protocol.

Show system services ssh

If the SSH connection-limit is not set to 4 or an organization-defined value, this is a finding.'
  desc 'fix', 'Configure the SSH protocol with a rate limit.

[edit]
set system services ssh rate-limit 4

Note: Juniper Networks recommends a best practice of 4 for the rate limit; however, the limit should be as restrictive as operationally practical.'
  impact 0.5
  tag check_id: 'C-24907r513389_chk'
  tag severity: 'medium'
  tag gid: 'V-223234'
  tag rid: 'SV-223234r961620_rule'
  tag stig_id: 'JUSX-DM-000163'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-24895r513390_fix'
  tag 'documentable'
  tag legacy: ['SV-81033', 'V-66543']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  # Use input with a fallback to 4 if not defined
  ssh_rate_limit = input('ssh_rate_limit', value: 4)

  describe command('show configuration system services ssh | display set | match rate-limit') do
    its('stdout.strip') { should match(/^set system services ssh rate-limit #{ssh_rate_limit}$/) }
  end
end
