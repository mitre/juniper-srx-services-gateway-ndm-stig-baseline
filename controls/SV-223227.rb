control 'SV-223227' do
  title 'The Juniper SRX Services Gateway must use SSHv2 with privacy options to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions using SSH.'
  desc 'To protect the confidentiality of nonlocal maintenance sessions when using SSH communications, SSHv2, AES ciphers, and key-exchange commands are configured. 

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through an external network (e.g., the internet) or internal network. 

The SSHv2 protocol suite includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers. The key-exchange commands limit the key exchanges to FIPS and DOD-approved methods.'
  desc 'check', 'Verify SSHv2, AES ciphers, and key-exchange commands are configured to protect confidentiality.

[edit]
show system services ssh

If SSHv2 is not configured to use AES ciphers and key-exchange commands, this is a finding.'
  desc 'fix', 'Configure SSH confidentiality options to comply with DOD requirements.

[edit]
set system services ssh protocol-version v2
set system services ssh ciphers aes256-ctr
set system services ssh ciphers aes192-ctr
set system services ssh ciphers aes128-ctr
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh key-exchange ecdh-sha2-nistp521
set system services ssh key-exchange ecdh-sha2-nistp384
set system services ssh key-exchange ecdh-sha2-nistp256'
  impact 0.7
  tag check_id: 'C-24900r1056176_chk'
  tag severity: 'high'
  tag gid: 'V-223227'
  tag rid: 'SV-223227r1056177_rule'
  tag stig_id: 'JUSX-DM-000150'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-24888r1056111_fix'
  tag 'documentable'
  tag legacy: ['SV-81021', 'V-66531']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']

  describe command('show configuration system services ssh | display set | match "(protocol-version|ciphers|macs|key-exchange)"') do
    its('stdout.strip') { should match(/^set system services ssh protocol-version v2/) }
    its('stdout.strip') { should match(/^set system services ssh ciphers aes256-ctr/) }
    its('stdout.strip') { should match(/^set system services ssh ciphers aes192-ctr/) }
    its('stdout.strip') { should match(/^set system services ssh ciphers aes128-ctr/) }
    its('stdout.strip') { should match(/^set system services ssh macs hmac-sha2-512/) }
    its('stdout.strip') { should match(/^set system services ssh macs hmac-sha2-256/) }
    its('stdout.strip') { should match(/^set system services ssh key-exchange ecdh-sha2-nistp521/) }
    its('stdout.strip') { should match(/^set system services ssh key-exchange ecdh-sha2-nistp384/) }
    its('stdout.strip') { should match(/^set system services ssh key-exchange ecdh-sha2-nistp256'/) }
  end
end
