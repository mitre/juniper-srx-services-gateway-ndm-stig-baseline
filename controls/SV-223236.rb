control 'SV-223236' do
  title 'The Juniper SRX Services Gateway must be configured to use Junos 12.1 X46 or later to meet the minimum required version for DoD.'
  desc 'Earlier versions of Junos may have reached the end of life cycle support by the vendor. Junos 12.1X46 is not a UC APL certified version, while 12.1X46 is UC APL Certified. The SRX with Junos 12.1X46 has been NIAP certified as a firewall and VPN. Junos 12.1X46 contains a number of enhancements, particularly related to IPv6, that are relevant to the STIG.'
  desc 'check', 'Verify the version installed is Junos 12.1 X46 or later. In operational mode, type the following:

show version

If the Junos version installed is not 12.1 X46 or later, this is a finding.'
  desc 'fix', "Follow the manufacturer's instructions for upgrading the Junos version. Software updates must be from an approved site and follow approved DoD procedures and verification processes in accordance with site testing procedures."
  impact 0.5
  tag check_id: 'C-24909r513395_chk'
  tag severity: 'medium'
  tag gid: 'V-223236'
  tag rid: 'SV-223236r961863_rule'
  tag stig_id: 'JUSX-DM-000166'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-24897r513396_fix'
  tag 'documentable'
  tag legacy: ['SV-81037', 'V-66547']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
