control 'SV-223225' do
  title 'The Juniper SRX Services Gateway must securely configure SSHv2 FIPS 140-2/140-3 validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'To protect the integrity of nonlocal maintenance sessions, SSHv2 with HMAC algorithms for integrity checking must be configured. 

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through an external network (e.g., the internet) or internal network. The SSHv2 protocol suite includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Verify SSHv2 and HMAC algorithms for integrity checking.

[edit]
show system services ssh

If SSHv2 and integrity options are not configured in compliance with DOD requirements for nonlocal maintenance session, this is a finding.'
  desc 'fix', 'Configure SSH integrity options.

[edit]
set system services ssh protocol-version v2
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256'
  impact 0.7
  tag check_id: 'C-24898r1056105_chk'
  tag severity: 'high'
  tag gid: 'V-223225'
  tag rid: 'SV-223225r1056185_rule'
  tag stig_id: 'JUSX-DM-000147'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-24886r1056106_fix'
  tag 'documentable'
  tag legacy: ['SV-81019', 'V-66529']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
