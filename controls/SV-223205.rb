control 'SV-223205' do
  title 'The Juniper SRX Services Gateway must be configured to synchronize internal information system clocks with the primary and secondary NTP servers for the network.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on log events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources.'
  desc 'check', 'Verify the Juniper SRX is configured to synchronize internal information system clocks with the primary and secondary NTP sources.

[edit]
show system ntp

If the Juniper SRX is not configured to synchronize internal information system clocks with an NTP server, this is a finding.'
  desc 'fix', 'The following commands allow the device to keep time synchronized with the network. To designate a primary NTP server, add the “prefer” keyword to the server statement.

[edit]
set system ntp server <NTP-server1-IP> prefer
set system ntp source-address <MGT-IP-Address>
set system ntp server <NTP-server2-IP>
set system ntp source-address <MGT-IP-Address>'
  impact 0.5
  tag check_id: 'C-24878r513302_chk'
  tag severity: 'medium'
  tag gid: 'V-223205'
  tag rid: 'SV-223205r1015751_rule'
  tag stig_id: 'JUSX-DM-000094'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-24866r513303_fix'
  tag 'documentable'
  tag legacy: ['SV-80977', 'V-66487']
  tag cci: ['CCI-000366', 'CCI-004928', 'CCI-004922', 'CCI-001893']
  tag nist: ['CM-6 b', 'SC-45 (2) (a)', 'SC-45', 'AU-8 (2)']

  # Input value for expected NTP server IP address
  ntp_servers = input('ntp_server_address')

  # Ensure that at least one NTP server address is provided
  describe 'NTP server address input' do
    it 'should contain at least one address' do
      expect(ntp_servers).to be_an(Array)
      expect(ntp_servers).not_to be_empty
    end
  end

  # Proceed only if addresses are provided
  unless ntp_servers.empty?
    # Get the device's configured NTP settings
    config_cmd = command('show configuration system ntp | display set')

    # Get current NTP associations
    assoc_cmd = command('show ntp associations')

    # Loop through each expected NTP server
    ntp_servers.each do |server|
      # Check that server is present in the configuration
      describe "NTP configuration for server '#{server}'" do
        it 'should be configured in system ntp settings' do
          expect(config_cmd.stdout).to match(/set system ntp server #{Regexp.escape(server)}/)
        end
      end

      # Check that server appears in active NTP associations
      describe "NTP association status for server #{server}" do
        it 'should appear in ntp associations' do
          expect(assoc_cmd.stdout).to match(/#{Regexp.escape(server)}/)
        end
      end
    end
  end
end
