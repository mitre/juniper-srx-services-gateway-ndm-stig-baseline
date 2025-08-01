control 'SV-223193' do
  title 'The Juniper SRX Services Gateway must generate log records when administrator privileges are deleted.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device logs change-log events of severity info or any to an external syslog server.

[edit]
show system syslog

host <syslog server address> {
  any <info | any>;
  source-address <device address>;
}

-OR-

host <syslog server address> {
  change-log <info | any>;
  source-address <device address>;
}

If an external syslog host is not configured to log facility change-log severity <info | any>, or configured for facility any severity <info | any>, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host is configured to log facility change-log or any, and severity info or any. 

[edit system syslog]
set host <syslog server address> any <info | any> 

 -OR-

[edit]
set host <syslog server address> change-log <info | any>'
  impact 0.3
  tag check_id: 'C-24866r513269_chk'
  tag severity: 'low'
  tag gid: 'V-223193'
  tag rid: 'SV-223193r961812_rule'
  tag stig_id: 'JUSX-DM-000042'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-24854r513270_fix'
  tag 'documentable'
  tag legacy: ['SV-81053', 'V-66563']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # Input for expected external syslog host
  expected_syslog_host = input('external_syslog_host')

  # If the expected external syslog host is provided, run the syslog-related checks
  if expected_syslog_host && !expected_syslog_host.empty?
    # Check if the syslog configuration includes change-log logging
    describe command('show configuration system syslog') do
      its('stdout') { should match(/host\s+(\S+)\s+\{[^}]*change-log\s+(info|any);/) }
    end
  else
    # If no external syslog host is configured, skip the control and set impact to 0.0
    impact 0.0
    describe 'External Syslog Server Configuration' do
      skip 'Skipped because external_syslog_host input is not set.'
    end
  end
end
