control 'SV-223233' do
  title 'The Juniper SRX Services Gateway must configure the control plane to protect against or limit the effects of common types of Denial of Service (DoS) attacks on the device itself by configuring applicable system options and internet-options.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Juniper SRX uses the system commands, system internet-options, and screens to mitigate the impact of DoS attacks on device availability.'
  desc 'check', 'Verify the system options are configured to protect against DoS attacks.

[edit]
show system
show system internet-options

If the system and system-options which limit the effects of common types of DoS attacks are not configured in compliance with DoD requirements, this is a finding.'
  desc 'fix', 'Configure the system and system-options to protect against DoS attacks.

[edit]
set system no-redirects
set system no-ping-record-route
set system no-ping-time-stamp
set system internet-options icmpv4-rate-limit packet-rate 50
set system internet-options icmpv6-rate-limit packet-rate 50
set system internet-options no-ipip-path-mtu-discovery
set system internet-options no-source-quench
set system internet-options tcp-drop-synfin-set
set system internet-options no-ipv6-path-mtu-discovery
set system internet-options no-tcp-reset drop-all-tcp'
  impact 0.5
  tag check_id: 'C-24906r513386_chk'
  tag severity: 'medium'
  tag gid: 'V-223233'
  tag rid: 'SV-223233r961620_rule'
  tag stig_id: 'JUSX-DM-000162'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-24894r513387_fix'
  tag 'documentable'
  tag legacy: ['SV-81031', 'V-66541']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  # Input parameters for organization-defined packet rate limits
  org_icmpv4_rate_limit = input('icmpv4_rate_limit')
  org_icmpv6_rate_limit = input('icmpv6_rate_limit')
  
  # Retrieve system-level options related to DoS mitigation
  system_no_options = command('show configuration system | display set | match "(no-|internet-options)"').stdout.strip

  # Retrieve internet-options configs as an array of lines (trimmed)
  internet_options = command('show configuration system internet-options | display set').stdout.lines.map(&:strip)

  # Tests for system-level options
  describe 'System-level DoS mitigation options' do
    it 'should have no-redirects enabled' do
      expect(system_no_options).to match(/^set system no-redirects/)
    end

    it 'should have no-ping-record-route enabled' do
      expect(system_no_options).to match(/^set system no-ping-record-route/)
    end

    it 'should have no-ping-time-stamp enabled' do
      expect(system_no_options).to match(/^set system no-ping-time-stamp/)
    end
  end

  # Tests for internet-options
  describe 'Internet-options DoS mitigation settings' do
    it "should limit icmpv4 packet rate to #{org_icmpv4_rate_limit}" do
      expect(internet_options).to include("set system internet-options icmpv4-rate-limit packet-rate #{org_icmpv4_rate_limit}")
    end

    it "should limit icmpv6 packet rate to #{org_icmpv6_rate_limit}" do
      expect(internet_options).to include("set system internet-options icmpv6-rate-limit packet-rate #{org_icmpv6_rate_limit}")
    end

    it 'should disable ipip path mtu discovery' do
      expect(internet_options).to include('set system internet-options no-ipip-path-mtu-discovery')
    end

    it 'should disable source quench' do
      expect(internet_options).to include('set system internet-options no-source-quench')
    end

    it 'should drop tcp packets with synfin set' do
      expect(internet_options).to include('set system internet-options tcp-drop-synfin-set')
    end

    it 'should disable ipv6 path mtu discovery' do
      expect(internet_options).to include('set system internet-options no-ipv6-path-mtu-discovery')
    end

    it 'should drop all tcp resets' do
      expect(internet_options).to include('set system internet-options no-tcp-reset drop-all-tcp')
    end
  end

  # describe command('show configuration system | display set | match "(no-|internet-options)"') do
  #   # System-level options to mitigate DoS attacks
  #   its('stdout.strip') { should match(/^set system no-redirects/) }
  #   its('stdout.strip') { should match(/^set system no-ping-record-route/) }
  #   its('stdout.strip') { should match(/^set system no-ping-time-stamp/) }
    
  #   # Internet options limiting rates and disabling risky features
  #   its('stdout.strip') { should match(/^set system internet-options icmpv4-rate-limit packet-rate 50/) }
  #   its('stdout.strip') { should match(/^set system internet-options icmpv6-rate-limit packet-rate 50/) }
  #   its('stdout.strip') { should match(/^set system internet-options no-ipip-path-mtu-discovery/) }
  #   its('stdout.strip') { should match(/^set system internet-options no-source-quench/) }
  #   its('stdout.strip') { should match(/^set system internet-options tcp-drop-synfin-set/) }
  #   its('stdout.strip') { should match(/^set system internet-options no-ipv6-path-mtu-discovery/) }
  #   its('stdout.strip') { should match(/^set system internet-options no-tcp-reset drop-all-tcp/) }
  # end
end
