control 'SV-223216' do
  title 'The Juniper SRX Services Gateway must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

There are 2 approved methods for accessing the Juniper SRX which are, in order of preference, the SSH protocol and the console port.'
  desc 'check', 'Verify SSH is configured to use a replay-resistant authentication mechanism.

[edit]
show system services ssh

If SSH is not configured to use the MAC authentication protocol, this is a finding.'
  desc 'fix', 'Configure SSH to use a replay-resistant authentication mechanism. The following is an example stanza.

[edit]
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh macs hmac-sha1
set system services ssh macs hmac-sha1-96'
  impact 0.5
  tag check_id: 'C-24889r513335_chk'
  tag severity: 'medium'
  tag gid: 'V-223216'
  tag rid: 'SV-223216r960993_rule'
  tag stig_id: 'JUSX-DM-000124'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-24877r513336_fix'
  tag 'documentable'
  tag legacy: ['SV-81003', 'V-66513']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']

  # Run CLI command to get all configured SSH MAC algorithms
  macs_output = command('show configuration system services ssh | display set | match "set system services ssh macs"').stdout.lines.map(&:strip)

  describe 'SSH MAC algorithms' do
    it 'should include only strong hmac-sha2 MACs' do
      # Check that each configured MAC is either hmac-sha2-256 or hmac-sha2-512.
      # If any weak algorithm (e.g., hmac-sha1) is found, this will fail.
      expect(macs_output).to all(match(/^set system services ssh macs hmac-sha2-(256|512)$/))
    end
  end
end
