control 'SV-223202' do
  title 'The Juniper SRX Services Gateway must implement logon roles to ensure only authorized roles are allowed to install software and updates.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. This requirement applies to code changes and upgrades for all network devices.

For example audit admins and the account of last resort are not allowed to perform this task.'
  desc 'check', 'To verify role-based access control has been configured, view the settings for each login class defined.

[edit]
show system login

View all login classes to see which roles are assigned the "Maintenance" or "request system software add" permissions. 

If login classes for user roles that are not authorized to install and update software are configured, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to allow only the information system security manager (ISSM) user account (or administrators/roles appointed by the ISSM) to select which auditable events are to be audited. To ensure this is the case, each ISSM-appointed role on the AAA must be configured for least privilege using the following stanzas for each role.

[edit]
show system login

Use the delete command or retype the command to remove the permission "Maintenance" or "request system software add" from any class that is not authorized to upgrade software on the device. An explicitly Deny for the command "request system software add" can also be used if some Maintenance commands are permitted.'
  impact 0.5
  tag check_id: 'C-24875r513293_chk'
  tag severity: 'medium'
  tag gid: 'V-223202'
  tag rid: 'SV-223202r1015750_rule'
  tag stig_id: 'JUSX-DM-000077'
  tag gtitle: 'SRG-APP-000378-NDM-000302'
  tag fix_id: 'F-24863r997563_fix'
  tag 'documentable'
  tag legacy: ['SV-80975', 'V-66485']
  tag cci: ['CCI-003980', 'CCI-001812']
  tag nist: ['CM-11 (2)', 'CM-11 (2)']

  # Check users assigned only authorized classes (roles) that include software install permission
  authorized_roles = input('authorized_software_install_roles')

  # Check if any login class allows software install via 'maintenance' permission
  describe command('show configuration | display set | match "system login class"') do
    its('stdout') { should_not match(/set system login class \S+ permissions.*maintenance/) }
  end

  # Ensure only authorized classes are used by users with software install ability
  users_output = command('show configuration | display set | match "system login user"').stdout.strip
  user_class_map = users_output.scan(/^set system login user (\S+) class (\S+)$/)

  user_class_map.each do |user, klass|
    describe "User '#{user}'" do
      if authorized_roles.include?(klass)
        it "is authorized to use role '#{klass}' for software installation" do
          expect(klass).to be_in authorized_roles
        end
      else
        class_config = command("show configuration system login class '#{klass}'").stdout
        describe "Class '#{klass}' used by user '#{user}'" do
          it 'should not include software install privileges' do
            expect(class_config).not_to match(/permissions.*maintenance/)
            expect(class_config).not_to match(/deny-commands.*request system software add/)
          end
        end
      end
    end
  end
end
