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

  # Minimum number of NTP servers required (e.g., 2)
  min_ntp_servers = input('min_ntp_servers')

  # Get the list of configured NTP servers from Junos config
  cmd = command('show configuration system ntp | display set | match "server"')

  # Fail immediately if no NTP servers are configured
  describe 'NTP server configuration presence' do
    it 'should have at least one NTP server configured' do
      expect(cmd.stdout.strip).not_to be_empty, 
        'No NTP servers are configured on the system.'
    end
  end

  # Proceed with further checks only if servers exist
  unless cmd.stdout.strip.empty?
    # Verify command ran successfully
    describe 'NTP configuration command' do
      it 'should execute successfully' do
        expect(cmd.exit_status).to eq 0
      end
    end

    # Parse configured servers - Extract the lines that actually configure NTP servers
    ntp_servers = cmd.stdout.lines.select { |line| line.match?(/^set system ntp server \S+/) }

    # Check that the count of configured NTP servers meets or exceeds minimum required
    describe ntp_servers do
      it "should include at least #{min_ntp_servers} NTP servers" do
        expect(ntp_servers.count).to be >= min_ntp_servers
      end
    end
  end
end
