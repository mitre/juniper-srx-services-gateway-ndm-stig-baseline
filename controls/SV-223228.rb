control 'SV-223228' do
  title 'For nonlocal maintenance sessions, the Juniper SRX Services Gateway must ensure only zones where management functionality is desired have host-inbound-traffic system-services configured.'
  desc 'Add a firewall filter to protect the management interface. Note: The dedicated management interface (if present), and an interface placed in the functional zone management, will not participate in routing network traffic. It will only support device management traffic.

The host-inbound-traffic feature of the SRX is an additional layer of security for system services. This function can be configured on either a per zone or a per interface basis within each individual security zone. By default, a security zone has all system services disabled, which means that it will not accept any inbound management or protocol requests on the control plane without explicitly enabling the service at either the interface or zone in the security zone stanzas.'
  desc 'check', 'Verify only those zones where management functionality is allowed have host-inbound-traffic system-services configured and that protocols such as HTTP and HTTPS are not assigned to these zones.

[edit]
show security zones functional-zone management

If zones configured for host-inbound-traffic system-services have protocols other than SSH configured, this is a finding.'
  desc 'fix', 'Remove host-inbound-traffic systems-services option from zones not authorized for management traffic.

Remove unauthorized protocols (e.g., HTTP, HTTPS) from management zones that are configured to allow host-inbound-traffic system-services.'
  impact 0.5
  tag check_id: 'C-24901r513371_chk'
  tag severity: 'medium'
  tag gid: 'V-223228'
  tag rid: 'SV-223228r961557_rule'
  tag stig_id: 'JUSX-DM-000152'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-24889r513372_fix'
  tag 'documentable'
  tag legacy: ['SV-81023', 'V-66533']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']

  # Input: array of zones allowed to have management system-services
  allowed_zones = input('allowed_mgmt_zones')

  # Get all zones configured with host-inbound-traffic system-services
  zones_with_mgmt_services_raw = command('show configuration security zones | display set | match "host-inbound-traffic system-services"').stdout

  # Extract zone names from the config lines
  zones_with_mgmt_services = zones_with_mgmt_services_raw.lines.map do |line|
    match = line.match(/^set security zones security-zone (\S+) host-inbound-traffic system-services/)
    # Return the zone name if it matches the expected pattern
    match ? match[1] : nil
  end.compact.uniq

  describe 'Zones with management system-services configured' do
    it 'should be a subset of allowed zones only' do
      unexpected_zones = zones_with_mgmt_services - allowed_zones
      expect(unexpected_zones).to be_empty, "Unexpected zones with management services enabled: #{unexpected_zones.join(', ')}"
    end
  end
end
