control 'SV-223195' do
  title 'The Juniper SRX Services Gateway must generate log records when privileged commands are executed.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device generates a log when login events occur.

[edit]
show system syslog

host <syslog server address> {
  any any;
  source-address <device address>;
}

If an external syslog host is not configured to log, or configured for facility any severity any, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host to log facility any and severity info or any. There are multiple ways to accomplish this, the following is an example.

[edit system syslog]
set host <syslog server address> any any'
  impact 0.3
  tag check_id: 'C-24868r513275_chk'
  tag severity: 'low'
  tag gid: 'V-223195'
  tag rid: 'SV-223195r961827_rule'
  tag stig_id: 'JUSX-DM-000044'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-24856r513276_fix'
  tag 'documentable'
  tag legacy: ['SV-81057', 'V-66567']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # First test: Check the device syslog configuration to confirm
  # it is set to send 'interactive-commands' logs of severity 'info' or 'any'
  describe command('show configuration system syslog') do
    its('stdout') { should match(/host\s+(\S+)\s+\{[^}]*interactive-commands\s+(info|any);/) }
  end

  # Second test: Verify that privileged commands are actually being logged
  # by searching the system log messages for typical CLI command log entries.
  describe 'Syslog messages for privileged commands' do
    # Run a command that filters the log messages for entries related to interactive commands
    subject { command('show log messages | match UI_CMDLINE_READ_LINE').stdout }

    # Expect to find lines indicating commands executed by a user
    it 'should include interactive command logs' do
      expect(subject).to match(/UI_CMDLINE_READ_LINE: User .+ command:/)
    end
  end  
end
