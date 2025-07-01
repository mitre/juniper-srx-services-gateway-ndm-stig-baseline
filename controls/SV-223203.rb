control 'SV-223203' do
  title 'If the loopback interface is used, the Juniper SRX Services Gateway must protect the loopback interface with firewall filters for known attacks that may exploit this interface.'
  desc 'The loopback interface is a logical interface and has no physical port. Since the interface and addresses ranges are well-known, this port must be filtered to protect the Juniper SRX from attacks.'
  desc 'check', 'If the loopback interface is not used, this is not applicable.

Verify the loopback interface is protected by firewall filters.

[edit]
show interfaces lo0

If the loopback interface is not configured with IPv6 and IPv4 firewall filters, this is a finding.'
  desc 'fix', 'If the loopback interface is used, configure firewall filters. The following is an example of configuring a loopback address with filters on the device. It shows the format of both IPv4 and IPv6 addresses being applied to the interface. The first two commands show firewall filters being applied to the interface.

[edit]
set interfaces lo0 unit 0 family inet filter input protect_re
set interfaces lo0 unit 0 family inet6 filter input protect_re-v6
set interfaces lo0 unit 0 family inet address 1.1.1.250/32
set interfaces lo0 unit 0 family inet6 address 2100::250/128'
  impact 0.5
  tag check_id: 'C-24876r513296_chk'
  tag severity: 'medium'
  tag gid: 'V-223203'
  tag rid: 'SV-223203r961863_rule'
  tag stig_id: 'JUSX-DM-000084'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-24864r513297_fix'
  tag 'documentable'
  tag legacy: ['SV-80505', 'V-66015']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  
  # Get the entire lo0 configuration block
  lo0_config = command('show configuration interfaces lo0').stdout.strip

  if lo0_config.empty?
    # Skip control if lo0 is not configured at all
    impact 0.0
    describe 'Loopback interface lo0' do
      skip 'lo0 is not configured — skipping all filter checks.'
    end
  else

    # --- IPv4 (inet) Checks ---
    # Check if an IPv4 address is configured under lo0
    describe 'IPv4 address configured on lo0' do
      it 'should include a family inet address' do
        expect(lo0_config).to match(/family inet\s+{\s+.*address\s+/m)
      end
    end

    # If an inet address is present, check for an input filter
    if lo0_config =~ /family inet\s+{\s+.*address\s+/m
      ipv4_filter_match = lo0_config.match(/family inet\s+{\s+filter\s+{\s+input\s+(\S+);/m)

      describe 'IPv4 input filter' do
        it 'should be applied to lo0 inet family' do
          expect(ipv4_filter_match).not_to be_nil
        end
      end

      # If a filter is found, verify its definition exists and includes valid terms
      if ipv4_filter_match
        filter_name = ipv4_filter_match[1]
        describe command("show configuration firewall family inet filter #{filter_name}") do
          its('stdout') { |out|
            expect(out).to match(/term .* from/)
            expect(out).to match(/term .* then/)
          }
        end
      end
    end

    # --- IPv6 (inet6) Checks ---
    # Check if an IPv6 address is configured under lo0
    describe 'IPv6 address configured on lo0' do
      it 'should include a family inet6 address' do
        expect(lo0_config).to match(/family inet6\s+{\s+.*address\s+/m)
      end
    end

    # If an inet6 address is present, check for an input filter
    if lo0_config =~ /family inet6\s+{\s+.*address\s+/m
      ipv6_filter_match = lo0_config.match(/family inet6\s+{\s+filter\s+{\s+input\s+(\S+);/m)

      describe 'IPv6 input filter' do
        it 'should be applied to lo0 inet6 family' do
          expect(ipv6_filter_match).not_to be_nil
        end
      end

      # If a filter is found, verify its definition exists and includes valid terms
      if ipv6_filter_match
        filter_name = ipv6_filter_match[1]
        describe command("show configuration firewall family inet6 filter #{filter_name}") do
          its('stdout') { |out|
            expect(out).to match(/term .* from/)
            expect(out).to match(/term .* then/)
          }
        end
      end
    end
  end
end
