control 'SV-223180' do
  title 'The Juniper SRX Services Gateway must limit the number of concurrent sessions to a maximum of 10 or less for remote access using SSH.'
  desc 'The connection-limit command limits the total number of concurrent SSH sessions. To help thwart brute force authentication attacks, the connection limit should be as restrictive as operationally practical

Juniper Networks recommends the best practice of setting 10 (or less) for the connection-limit.

This configuration will permit up to 10 users to log in to the device simultaneously, but an attempt to log an 11th user into the device will fail. The attempt will remain in a waiting state until a session is terminated and made available.'
  desc 'check', 'Verify the Juniper SRX sets a connection-limit for the SSH protocol.

Show system services ssh

If the SSH connection-limit is not set to 10 or less, this is a finding.'
  desc 'fix', 'Configure the SSH protocol to limit connection and sessions per connection.

[edit]
set system services ssh connection-limit 10
set system services ssh max-sessions-per-connection 1'
  impact 0.3
  tag check_id: 'C-24853r513233_chk'
  tag severity: 'low'
  tag gid: 'V-223180'
  tag rid: 'SV-223180r960735_rule'
  tag stig_id: 'JUSX-DM-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-24841r513234_fix'
  tag 'documentable'
  tag legacy: ['SV-81039', 'V-66549']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']


  # Check the SSH connection limit
  describe command('show configuration system services ssh | display set') do
    let(:ssh_config) { subject.stdout }

    it 'should include a maximum session limit of 10 or less' do
      expect(ssh_config).to match(/set system services ssh connection-limit \d+/)

      limit_line = ssh_config[/set system services ssh connection-limit (\d+)/, 1]
      expect(limit_line.to_i).to be <= 10
    end
  end  
end
