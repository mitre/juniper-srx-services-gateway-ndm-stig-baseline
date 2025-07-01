control 'SV-223223' do
  title 'The Juniper SRX Services Gateway must use the SHA256 or later protocol for password authentication for local accounts using password authentication (i.e., the root account and the account of last resort).'
  desc 'Passwords must be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the default local password enforces this requirement by entering the following in configuration mode.

[edit]
show system login password

If the password format is not set to SHA256 or higher, this is a finding.'
  desc 'fix', 'Enter the following example command from the configuration mode.
 
[edit]
set system login password format sha256'
  impact 0.7
  tag check_id: 'C-24896r1056102_chk'
  tag severity: 'high'
  tag gid: 'V-223223'
  tag rid: 'SV-223223r1056174_rule'
  tag stig_id: 'JUSX-DM-000136'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-24884r1056103_fix'
  tag 'documentable'
  tag legacy: ['SV-81017', 'V-66527']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe command('show configuration system login password | display set') do
    its('stdout') { should match(/^set system login password format (sha256|sha512)$/) }
  end
end
