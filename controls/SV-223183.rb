control 'SV-223183' do
  title 'For local accounts created on the device, the Juniper SRX Services Gateway must automatically generate log records for account disabling events.'
  desc 'When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized, active accounts remain enabled and available for use when required. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.

An AAA server is required for account management in accordance with CCI-000370. Only a single account of last resort is permitted on the local device. However, since it is still possible for administrators to create local accounts either maliciously or to support mission needs, the SRX must be configured to log account management events.

To log local account management events, ensure at least one external syslog server is configured to log facility any or facility change-log, and severity info or severity any.'
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
  impact 0.5
  tag check_id: 'C-24856r513242_chk'
  tag severity: 'medium'
  tag gid: 'V-223183'
  tag rid: 'SV-223183r960783_rule'
  tag stig_id: 'JUSX-DM-000017'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-24844r513243_fix'
  tag 'documentable'
  tag legacy: ['SV-80953', 'V-66463']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']

  # Check the syslog configuration for logging account disablement events
  # This command checks the syslog configuration for logging account disablement events
  # It ensures that the syslog is set to log change-log events with severity info or any
  # and that it is configured to log to a valid file or remote host destination
  # The command output is expected to match the specified patterns for proper logging
  describe command('show configuration system syslog | display set') do
    let(:syslog_config) { subject.stdout }

    it 'should log configuration changes which include account disablement events' do
      expect(syslog_config).to match(/set system syslog .+ change/)
    end

    it 'should log to a file or remote host for audit tracking' do
      expect(syslog_config).to match(/set system syslog (file|host) .+ any .+/)
    end
  end 
end
