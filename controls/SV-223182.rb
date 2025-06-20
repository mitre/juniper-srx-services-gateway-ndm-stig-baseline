control 'SV-223182' do
  title 'For local accounts created on the device, the Juniper SRX Services Gateway must automatically generate log records for account modification events.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to modify existing accounts to increase/decrease privileges. Notification of account modification events help to mitigate this risk. Auditing account modification events provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.

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
  tag check_id: 'C-24855r513239_chk'
  tag severity: 'medium'
  tag gid: 'V-223182'
  tag rid: 'SV-223182r960780_rule'
  tag stig_id: 'JUSX-DM-000016'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-24843r513240_fix'
  tag 'documentable'
  tag legacy: ['SV-80951', 'V-66461']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']

  # Check the syslog configuration for logging account modification events
  describe command('show configuration system syslog | display set') do
    let(:syslog_config) { subject.stdout }

    it 'should log configuration changes which include account modifications' do
      expect(syslog_config).to match(/set system syslog .+ change/)
    end

    it 'should log to a valid file or remote host destination' do
      expect(syslog_config).to match(/set system syslog (file|host) .+ any .+/)
    end
  end
end
