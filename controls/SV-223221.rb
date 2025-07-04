control 'SV-223221' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce password complexity by requiring at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the default local password enforces password complexity by requiring at least one numeric character be used.

[edit]
show system login password

If the minimum numerics are not set to at least 1, this is a finding.'
  desc 'fix', 'Configure the default local password to enforce password complexity by requiring at least one numeric character be used.

[edit]
set system login password minimum -numerics to 1'
  impact 0.5
  tag check_id: 'C-24894r513350_chk'
  tag severity: 'medium'
  tag gid: 'V-223221'
  tag rid: 'SV-223221r1015756_rule'
  tag stig_id: 'JUSX-DM-000132'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-24882r997584_fix'
  tag 'documentable'
  tag legacy: ['SV-81013', 'V-66523']
  tag cci: ['CCI-004066', 'CCI-000194']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)']

  # Check the minimum numerics setting for local password complexity
  # The command 'show configuration system login password' will show the current password policy settings.
  describe command('show configuration system login password | display set | match minimum-numerics') do
    its('stdout.strip') { should match(/^set system login password minimum-numerics\s+[1-9]\d*/) }
  end
end
