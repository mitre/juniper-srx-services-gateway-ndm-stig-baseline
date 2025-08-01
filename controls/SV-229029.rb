control 'SV-229029' do
  title 'The Juniper SRX Services Gateway must reveal log messages or management console alerts only to the ISSO, ISSM, and SA roles).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives.

Although, based on policy, administrator accounts must be created on the AAA server, thus this requirement addresses the creation of unauthorized accounts on the Juniper SRX itself. This does not negate the need to address this requirement on the AAA server and the event monitoring server (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers)."
  desc 'check', 'Obtain a list of authorized user names that are authorized to view the audit log and console notification messages. Verify classes are created that separate administrator roles based on authorization. View user classes and class members by typing the following commands.

[edit]
show system login

View class assignment for all users and template users configured on the Juniper SRX. Users with login classes audit-admin, security-admin, and system-admin have permission to view error message in logs and/or notifications. 

If classes or users that are not authorized to have access to the logs (e.g., crypto-admin) have permissions to view or access error message in logs and/or notifications, this is a finding.'
  desc 'fix', 'Configure login classes and permissions and assign only authorized users to each class.

[edit]
show system login

If any classes are mapped to the audit-admin, security-admin, or system-admin login templates, delete the command from the class by typing delete in front of the command or retyping the command with the permission removed from the list.

Example configuration:
set system login class audit-admin allow-commands "(show log *)|(clear log *)|(monitor
log *)"
set system login class audit-admin allow-configuration "(system syslog)"
set system login class emergency permissions all
set system login class emergency login-alarms
set system login class security-admin login-alarms
set system login class system-admin login-alarms'
  impact 0.5
  tag check_id: 'C-31344r518263_chk'
  tag severity: 'medium'
  tag gid: 'V-229029'
  tag rid: 'SV-229029r961863_rule'
  tag stig_id: 'JUSX-DM-000165'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31321r518264_fix'
  tag 'documentable'
  tag legacy: ['SV-81035', 'V-66545']
  tag cci: ['CCI-000366', 'CCI-000416']
  tag nist: ['CM-6 b', 'CM-8 (3) (a)']

  authorized_classes = input('authorized_classes')

  describe command('show configuration system login | display set') do
    let(:login_config) { subject.stdout }

    authorized_classes.each do |cls|
      it "#{cls} should be allowed to view logs" do
        expect(login_config).to match(/set system login class #{cls} allow-commands "\(\s*show log \*\s*\)\|\(\s*clear log \*\s*\)\|\(\s*monitor log \*\s*\)"/)
      end
    end

    it 'should not allow unauthorized classes to use show/clear/monitor log' do
      login_config.scan(/set system login class (\S+) allow-commands "([^"]+)"/).each do |klass, cmds|
        next if authorized_classes.include?(klass)
        if cmds.match?(/show log|clear log|monitor log/)
          fail("Unauthorized class '#{klass}' has access to log commands: #{cmds}")
        end
      end
    end
  end
end
