control 'SV-223217' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

Compliance with this requirement also prevents the system from being configured with default or no passwords.'
  desc 'check', 'Verify the SRX password enforces this complexity requirement. In configuration mode, enter the following command.

[edit]
show system login password

If the minimum password length for local accounts is not set to at least a 15-character length, this is a finding.'
  desc 'fix', 'Set the global password option for all accounts created on the Juniper SRX.

[edit]
set system login password minimum-length 15

Note: This setting only enforces the minimum character password length for newly created passwords. The password of the existing account must be changed if it is not already complaint.

To set or change the root user password, in configuration mode enter the following command.

[edit]
set system root-authentication plain-text-password

When prompted, enter the password for the root user. 
Retype new password to confirm

To set or change the account of last resort, in configuration mode enter the following command.

[edit]
set system login user <name of the account of last resort> plain-text-password

When prompted, enter the password for the root user. 
Retype new password to confirm.'
  impact 0.5
  tag check_id: 'C-24890r513338_chk'
  tag severity: 'medium'
  tag gid: 'V-223217'
  tag rid: 'SV-223217r1015752_rule'
  tag stig_id: 'JUSX-DM-000128'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-24878r997573_fix'
  tag 'documentable'
  tag legacy: ['SV-81005', 'V-66515']
  tag cci: ['CCI-004066', 'CCI-000205']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)']

 # Execute CLI command to fetch the password policy config in set format
  password_policy_config = command('show configuration system login password | display set').stdout.strip

  describe 'Password policy configuration' do
    it 'should exist' do
      expect(password_policy_config).not_to be_empty
    end
  end

  if !password_policy_config.empty?
    # Parse the minimum-length value using a regex
    min_length_line = password_policy_config.lines.find { |line| line =~ /^set system login password minimum-length (\d+)/ }
    min_length_value = min_length_line&.match(/^set system login password minimum-length (\d+)/)&.captures&.first&.to_i

    describe 'Minimum password length' do
      it 'should be explicitly configured' do
        expect(min_length_line).not_to be_nil, 'Minimum password length is not configured.'
      end

      it 'should be set to 15 characters or more' do
        expect(min_length_value).to be >= 15
      end
    end
  end
end
