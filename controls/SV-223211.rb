control 'SV-223211' do
  title 'The Juniper SRX Services Gateway must use and securely configure SNMPv3 if SNMP is enabled.'
  desc "To prevent nonsecure protocol communications with the organization's local SNMPv3 services, the SNMP client on the Juniper SRX must be configured for proper identification and strong cryptographically based protocol for authentication.

SNMPv3 defines a user-based security model (USM) and a view-based access control model (VACM). SNMPv3 USM provides data integrity, data origin authentication, message replay protection, and protection against disclosure of the message payload. SNMPv3 VACM provides access control to determine whether a specific type of access (read or write) to the management information is allowed.

The Junos operating system allows the use of SNMPv3 to monitor or query the device for management purposes. Junos does not allow SNMPv3, of any type, to be used to make configuration changes to the device. SNMPv3 is disabled by default and must be enabled for use. SNMPv3 is the DOD-preferred method for monitoring the device securely. If SNMPv3 is not being used, it must be disabled. The commands in the Fix Text will configure SNMPv3. The Junos operating system allows the use of FIPS 140-2/140-3 validated protocols for secure connections."
  desc 'check', 'If an SNMP stanza does not exist, this is not a finding.

Verify SNMPv3 is enabled and configured.

[edit]
show snmp

If versions earlier than SNMPv3 are enabled, this is a finding.'
  desc 'fix', 'Enable and configure SNMPv3 and configure a trap and community string.

[edit]
set snmp location <LOCATION-NAME>
set snmp v3 usm local-engine user <USER-NAME> privacy-AES128 authentication-sha256
set snmp v3 vacm security-to-group security-model usm security-name <SECURITY-NAME> group <GROUP-NAME>
set snmp v3 vacm access group <GROUP-NAME> default-context-prefix security-model usm
security-level privacy read-view all
set snmp v3 vacm access group <GROUP-NAME> default-context-prefix security-model usm
security-level privacy notify-view all
set snmp v3 target-address <target-address-name> tag-list <SNMP-trap-receiver>
set snmp v3 target-address <TARGER-ADDRESS-NAME> target-parameters <PARMS-NAME>
set snmp v3 target-parameters <PARMS-NAME> parameters message-processing-model v3
set snmp v3 target-parameters <PARMS-NAME> parameters security-model usm
set snmp v3 target-parameters <PARMS-NAME> parameters security-level privacy
set snmp v3 target-parameters <PARMS-NAME> parameters security-name <SECURITY-NAME>
set snmp v3 target-parameters <PARMS-NAME> notify-filter device-traps
set snmp v3 notify <SNMP-TRAPS> type trap
set snmp v3 notify <SNMP-TRAPS> tag <SNMP-TRAP-RECEIVER>
set snmp v3 notify-filter device-traps oid jnxChassisTraps include
set snmp v3 notify-filter device-traps oid jnxChassisOKTraps include
set snmp v3 notify-filter device-traps oid system include
set snmp v3 notify-filter device-traps oid .1 include
set snmp v3 notify-filter device-traps oid snmpMIBObjects include
set snmp engine-id use-mac-address
set snmp view all oid .1 include
set snmp view all oid system include
set snmp view all oid jnxBoxAnatomy include
set snmp view all oid snmpMIBObjects include'
  impact 0.7
  tag check_id: 'C-24884r1056099_chk'
  tag severity: 'high'
  tag gid: 'V-223211'
  tag rid: 'SV-223211r1056173_rule'
  tag stig_id: 'JUSX-DM-000111'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24872r1056100_fix'
  tag 'documentable'
  tag legacy: ['SV-80941', 'V-66451']
  tag cci: ['CCI-000382', 'CCI-001967']
  tag nist: ['CM-7 b', 'IA-3 (1)']

  # Get the full SNMP configuration stanza
  snmp_config = command('show configuration snmp | display set').stdout

  if snmp_config.strip.empty?
    # ✅ SNMP is not enabled — this is NOT a finding
    impact 0.0
    describe 'SNMP configuration' do
      skip 'SNMP is not configured on the device. Skipping SNMPv3 security checks — this is not a finding.'
    end
  else
    # ✅ SNMP is enabled — continue checking for secure SNMPv3 usage

    describe 'SNMPv1/v2c is disabled' do
      it 'should not include SNMP community strings (SNMPv1/v2c)' do
        expect(snmp_config).not_to match(/^set snmp community /)
      end
    end

    describe 'SNMPv3 user configuration' do
      it 'should include a v3 USM user definition' do
        expect(snmp_config).to match(/set snmp v3 usm local-engine user \S+/)
      end
    end

    describe 'SNMPv3 authentication protocol' do
      it 'should specify an authentication method like SHA' do
        expect(snmp_config).to match(/authentication-sha/)
      end
    end

    describe 'SNMPv3 privacy protocol' do
      it 'should specify a privacy protocol like AES' do
        expect(snmp_config).to match(/privacy-aes(128|192|256)/)
      end
    end
  end  
end
