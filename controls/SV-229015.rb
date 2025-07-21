control 'SV-229015' do
  title 'For local accounts, the Juniper SRX Services Gateway must generate an alert message to the management console and generate a log event record that can be forwarded to the ISSO and designated system administrators when local accounts are created.'
  desc 'An authorized insider or individual who maliciously creates a local account could gain immediate access from a remote location to privileged information on a critical security device. Sending an alert to the administrators and ISSO when this action occurs greatly reduces the risk that accounts will be surreptitiously created.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites). The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. Alerts must be sent immediately to designated individuals. Alerts may be sent via NMS, SIEM, Syslog configuration, SNMP trap or notice, or manned console message.

Although, based on policy, administrator accounts must be created on the AAA server, thus this requirement addresses the creation of unauthorized accounts on the Juniper SRX itself. This does not negate the need to address this requirement on the AAA server and the event monitoring server (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers).'
  desc 'check', 'Verify the device is configured to display change-log events of severity info.

[edit]
show system syslog

If the system is not configured to display account creation actions on the management console and generate an event log message to the Syslog server and a local file, this is a finding.'
  desc 'fix', "Configure the Juniper SRX to generate and send a notification or log message immediately that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following commands configure the device to immediately display a message to any currently logged on administrator's console when changes are made to the configuration. This is an example method. Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

[edit]
set system syslog users * change-log <info | any> 
set system syslog host <IP-syslog-server> any any
set system syslog file account-actions change-log any any"
  impact 0.5
  tag check_id: 'C-31330r518221_chk'
  tag severity: 'medium'
  tag gid: 'V-229015'
  tag rid: 'SV-229015r961863_rule'
  tag stig_id: 'JUSX-DM-000019'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31307r518222_fix'
  tag 'documentable'
  tag legacy: ['SV-80933', 'V-66443']
  tag cci: ['CCI-000171', 'CCI-000366']
  tag nist: ['AU-12 b', 'CM-6 b']

  expected_syslog_host = input('external_syslog_host')
  syslog_minimum_severity = input('syslog_minimum_severity')

  if expected_syslog_host.to_s.strip.empty?
    impact 0.0
    describe 'External syslog host is not configured' do
      skip 'Skipping generation of alert message for accounts creation to the management console checks.'
    end
  else
    # --------------------------------
    # Check system syslog settings
    describe command('show configuration system syslog | display set') do
      let(:syslog_config) { subject.stdout }

      # Ensure that all user-initiated changes are logged to the change-log with the expected severity
      it 'should configure syslog users for change-log with correct severity' do
        expect(syslog_config).to match(/set system syslog users \* change-log #{syslog_minimum_severity}/)
      end

      # Check that logs are being forwarded to the approved external syslog server
      it 'should forward logs to the designated syslog server' do
        expect(syslog_config).to match(/set system syslog host #{Regexp.escape(expected_syslog_host)} any any/)
      end

      # Confirm that account-related log events are sent to the proper log file
      it 'should log account actions to the change-log file' do
        expect(syslog_config).to match(/set system syslog file account-actions change-log any any/)
      end
    end

    # ------------------------------------------------------------------
    # Optional: Check for commit script used to detect account creation
    describe command('show configuration system scripts commit | display set') do
      let(:script_config) { subject.stdout }

      it 'should define at least one commit script' do
        expect(script_config).to match(/^set system scripts commit file/)
      end

      # Verify that commit scripts are present — these can be used to trigger notifications (e.g., for account creation)
      it 'should reference a script likely used to monitor account creation (e.g., checks for "set system login user")' do
        # Customize if specific specific filenames or script are expected
        expect(script_config).to match(/set system scripts commit file/) 
        # Match specific expected script names (adjust this regex to fit your naming convention)
        # expect(script_config).to match(/set system scripts commit file .*user-monitor.*\.(slax|xsl|py)/)
      end
    end
  end
end
