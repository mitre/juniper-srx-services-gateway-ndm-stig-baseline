control 'SV-223222' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce password complexity by requiring at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the default local password enforces password complexity by requiring at least one special character be used.

[edit]
show system login password

If the minimum-punctuation is not set to at least 1, this is a finding.'
  desc 'fix', 'Configure the default local password to enforce password complexity by requiring at least one special character be used.

[edit]
set system login password minimum-punctuations 1'
  impact 0.5
  tag check_id: 'C-24895r513353_chk'
  tag severity: 'medium'
  tag gid: 'V-223222'
  tag rid: 'SV-223222r1015757_rule'
  tag stig_id: 'JUSX-DM-000133'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-24883r513354_fix'
  tag 'documentable'
  tag legacy: ['SV-81015', 'V-66525']
  tag cci: ['CCI-004066', 'CCI-001619']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)']

  describe command('show configuration system login password | display set | match minimum-punctuations') do
    its('stdout.strip') { should match(/^set system login password minimum-punctuations\s+[1-9]\d*/) }
  end
end
