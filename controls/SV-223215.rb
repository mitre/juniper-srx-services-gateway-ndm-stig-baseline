control 'SV-223215' do
  title 'The Juniper SRX Services Gateway must be configured with only one local user account to be used as the account of last resort.'
  desc 'Without centralized management, credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. 

Local accounts are configured using the local password authentication method which does not meet the multifactor authentication criteria. The account of last resort is a group authenticator which does not provide nonrepudiation, thus must be used only rare cases where the device must be accessed using the local console and an individual authenticator is not possible, including when network access is not available.'
  desc 'check', 'Verify only a single local account has an authentication stanza and that the name is the account of last resort.

[edit]
show system login

user <account of last resort> {
  uid 2001;
  class <appropriate class name>;
  authentication { <--- This stanza permits local login
    encrypted-password "$sha2$22895$aVBPaRVa$o6xIqNSYg9D7yt8pI47etAjZV9uuwHrhAFT6R021HNsy"; ## SECRET-DATA
  }
}

OR

user <template account> {
  uid 2001;
  class <appropriate class name>;
}

If accounts other than the account of last resort contain an authentication stanza, and that account is not documented, this is a finding.'
  desc 'fix', 'If more than one account has an authentication stanza, and it is not documented, delete the authentication stanza (if the account is a template account) or the entire account (if the account is unauthorized or no longer needed).

To delete a template account:

[edit]
delete system login user <account name> authentication
commit

To delete an unneeded or unauthorized account:

[edit]
delete system login user <account name>'
  impact 0.5
  tag check_id: 'C-24888r513332_chk'
  tag severity: 'medium'
  tag gid: 'V-223215'
  tag rid: 'SV-223215r1043177_rule'
  tag stig_id: 'JUSX-DM-000115'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24876r513333_fix'
  tag 'documentable'
  tag legacy: ['SV-81001', 'V-66511']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  # Fetch configured local users
  user_config = command('show configuration system login | display set | match "^set system login user"').stdout

  # Extract all defined users
  user_lines = user_config.lines.select { |line| line =~ /^set system login user (\S+)/ }
  usernames = user_lines.map { |line| line.match(/^set system login user (\S+)/)[1] }.uniq

  # Remove root from the user list
  local_non_root_users = usernames.reject { |u| u == 'root' }

  describe 'Number of local user accounts (excluding root)' do
    it 'should be exactly one account used as account of last resort' do
      expect(local_non_root_users.count).to eq(1)
    end
  end  
end
