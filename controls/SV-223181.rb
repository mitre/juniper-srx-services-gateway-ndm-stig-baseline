control 'SV-223181' do
  title 'For local accounts created on the device, the Juniper SRX Services Gateway must automatically generate log records for account creation events.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.

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
  tag check_id: 'C-24854r513236_chk'
  tag severity: 'medium'
  tag gid: 'V-223181'
  tag rid: 'SV-223181r960777_rule'
  tag stig_id: 'JUSX-DM-000015'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-24842r513237_fix'
  tag 'documentable'
  tag legacy: ['SV-80949', 'V-66459']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']

  external_syslog = input('external_syslog_host')

  # Check the syslog configuration for logging account management events
  describe command('show configuration system syslog | display set') do
    let(:syslog_config) { subject.stdout }

    it 'should include logging for change events or configuration commits' do
      expect(syslog_config).to match(/set system syslog (file|host) .+ (change-log|any) .+/)
    end

    it 'should log to a file or remote host' do
      expect(syslog_config).to match(/set system syslog (file|host) .+ any .+/)
    end

    if external_syslog && !external_syslog.to_s.strip.empty?
      it "should log to the specified external syslog server #{external_syslog}" do
        expect(syslog_config).to match(/set system syslog host #{Regexp.escape(external_syslog)} .+ any .+/)
      end
    else
      skip 'External syslog host input is not set; skipping remote syslog checks.'
    end    
  end
end
