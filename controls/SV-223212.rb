control 'SV-223212' do
  title 'The Juniper SRX Services Gateway must ensure SSH is disabled for root user logon to prevent remote access using the root account.'
  desc 'Since the identity of the root account is well-known for systems based upon Linux or UNIX and this account does not have a setting to limit access attempts, there is risk of a brute force attack on the password. Root access would give superuser access to an attacker. Preventing attackers from remotely accessing management functions using root account mitigates the risk that unauthorized individuals or processes may gain superuser access to information or privileges.

A separate account should be used for access and then the administrator can sudo to root when necessary.'
  desc 'check', 'Use the CLI to view this setting for disabled for SSH. 

[edit]
show system services ssh root-login

If SSH is not disabled for the root user, this is a finding.'
  desc 'fix', 'From the configuration mode, enter the following commands to disable root-login using SSH.

[edit]
set system services ssh root-login deny'
  impact 0.5
  tag check_id: 'C-24885r513323_chk'
  tag severity: 'medium'
  tag gid: 'V-223212'
  tag rid: 'SV-223212r1043177_rule'
  tag stig_id: 'JUSX-DM-000112'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24873r513324_fix'
  tag 'documentable'
  tag legacy: ['SV-80993', 'V-66503']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  # Run the command to display SSH configuration
  ssh_config = command('show configuration system services ssh | display set').stdout

  # Skip if SSH is not configured at all
  if ssh_config.strip.empty?
    describe 'SSH service' do
      skip 'SSH is not configured — root login restriction not applicable.'
    end
  else
    describe 'SSH root login setting' do
      it 'should explicitly deny root login' do
        #expect(ssh_config).to match(/^set system services ssh root-login deny$/)
        expect(ssh_config).to match(/^set system services ssh root-login deny\b/)
      end
    end
  end
end
