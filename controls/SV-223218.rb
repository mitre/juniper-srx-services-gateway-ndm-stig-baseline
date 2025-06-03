control 'SV-223218' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce password complexity by setting the password change type to character sets.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

The password change-type command specifies whether a minimum number of character-sets or a minimum number of character-set transitions are enforced. The DOD requires this setting be set to character-sets.'
  desc 'check', 'Verify the default local password enforces password complexity by setting the password change type to character sets.

[edit]
show system login password

If the password change-type is not set to character-sets, this is a finding.'
  desc 'fix', 'Configure the default local password to enforce password complexity by setting the password change type to character sets.

[edit]
set system login password change-type character-sets'
  impact 0.5
  tag check_id: 'C-24891r997575_chk'
  tag severity: 'medium'
  tag gid: 'V-223218'
  tag rid: 'SV-223218r1015753_rule'
  tag stig_id: 'JUSX-DM-000129'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-24879r997576_fix'
  tag 'documentable'
  tag legacy: ['SV-81007', 'V-66517']
  tag cci: ['CCI-004066', 'CCI-000192']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)']
end
