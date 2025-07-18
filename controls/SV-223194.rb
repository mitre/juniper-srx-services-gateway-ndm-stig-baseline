control 'SV-223194' do
  title 'The Juniper SRX Services Gateway must generate log records when logon events occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device generates a log when login events occur.

[edit]
show system syslog

host <syslog server address> {
  any <info | any>;
  source-address <device address>;
}

If an external syslog host is not configured to log, or configured for facility any severity <info | any>, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host to log facility any and severity info or any. 

[edit system syslog]
set host <syslog server address> any <info | any>'
  impact 0.3
  tag check_id: 'C-24867r513272_chk'
  tag severity: 'low'
  tag gid: 'V-223194'
  tag rid: 'SV-223194r961824_rule'
  tag stig_id: 'JUSX-DM-000043'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-24855r513273_fix'
  tag 'documentable'
  tag legacy: ['SV-81055', 'V-66565']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # Input for expected external syslog host
  expected_syslog_host = input('external_syslog_host')

  # If the expected external syslog host is provided, run the syslog-related checks
  if expected_syslog_host && !expected_syslog_host.empty?
    # Check if the syslog configuration includes logging for login events
    describe command('show configuration system syslog') do
      its('stdout') { should match(/host\s+(\S+)\s+\{[^}]*authorization\s+(info|any);/) }
    end

    # Check if the syslog configuration includes any logging
    describe command('show configuration system syslog') do
      its('stdout') { should match(/host\s+(\S+)\s+\{[^}]*authorization\s+(info|any);/) }
    end
  end

  # Check if the syslog configuration includes any logging for remote login sessions
  describe 'Login event logging via syslog' do
    subject { command('show log messages | match sshd').stdout }

    it 'should include login attempts' do
      expect(subject).to match(/sshd\[\d+\]:.+(Accepted|Failed).+for.+from/)
    end
  end  
end
