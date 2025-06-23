control 'SV-223224' do
  title 'For nonlocal maintenance sessions using SNMP, the Juniper SRX Services Gateway must use and securely configure SNMPv3 with SHA256 or higher to protect the integrity of maintenance and diagnostic communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through an external network (e.g., the internet) or internal network. 
 
The Juniper SRX allows the use of SNMP to monitor or query the device in support of diagnostic information. SNMP cannot be used to make configuration changes; however, it is a valuable diagnostic tool. SNMP is disabled by default and must be enabled for use. SNMPv3 is the DOD-required version but must be configured to be used securely.'
  desc 'check', 'Verify SNMP is configured for version 3.

[edit]
show snmp v3
 
If SNMPv3 is not configured for version 3 using SHA256 or higher, this is a finding.'
  desc 'fix', 'Configure snmp to use version 3 with SHA256 authentication.

[edit]
set snmp v3 usm local-engine user <NAME> authentication-sha256'
  impact 0.7
  tag check_id: 'C-24897r1056113_chk'
  tag severity: 'high'
  tag gid: 'V-223224'
  tag rid: 'SV-223224r1056178_rule'
  tag stig_id: 'JUSX-DM-000146'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-24885r1056114_fix'
  tag 'documentable'
  tag legacy: ['SV-80943', 'V-66453']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']


  # Pull the SNMP configuration from the device
  snmp_config = command('show configuration snmp | display set').stdout.strip

  if snmp_config.empty?
    # No SNMP configuration present — this is not a finding
    describe 'SNMP configuration' do
      skip 'SNMP is not configured — this control is not applicable.'
    end
  else
    # Fail if SNMP community strings (SNMPv1/v2c) are configured
    describe 'SNMPv1/v2c community strings' do
      it 'should not be configured' do
        expect(snmp_config).not_to match(/^set snmp community /)
      end
    end

    # Confirm SNMPv3 user with SHA256+ authentication is configured
    describe 'SNMPv3 authentication method' do
      it 'should use SHA-256 or stronger' do
        expect(snmp_config).to match(/authentication-sha-256|authentication-sha-384|authentication-sha-512/)
      end
    end

    # Confirm SNMPv3 privacy method (encryption)
    describe 'SNMPv3 privacy protocol' do
      it 'should use AES encryption (128, 192, or 256)' do
        expect(snmp_config).to match(/privacy-aes(128|192|256)/)
      end
    end
  end  
end
