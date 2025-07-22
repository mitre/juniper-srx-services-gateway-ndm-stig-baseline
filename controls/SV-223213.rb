control 'SV-223213' do
  title 'The Juniper SRX Services Gateway must ensure access to start a UNIX-level shell is restricted to only the root account.'
  desc 'Restricting the privilege to create a UNIX-level shell limits access to this powerful function. System administrators, regardless of their other permissions, will need to also know the root password for this access, thus limiting the possibility of malicious or accidental circumvention of security controls.'
  desc 'check', 'Verify each login class is configured to deny access to the UNIX shell.

[edit]
show system login

If each configured login class is not configured to deny access to the UNIX shell, this is a finding.'
  desc 'fix', 'For each login class, add the following command to the stanza.

[edit]
set system login class <class name> deny-commands "(start shell)"'
  impact 0.5
  tag check_id: 'C-24886r513326_chk'
  tag severity: 'medium'
  tag gid: 'V-223213'
  tag rid: 'SV-223213r1043177_rule'
  tag stig_id: 'JUSX-DM-000113'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24874r513327_fix'
  tag 'documentable'
  tag legacy: ['SV-80997', 'V-66507']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  # Retrieve login configuration (includes both user and class settings)
  login_config = command('show configuration system login | display set').stdout

  # Parse user-to-class mappings from configuration lines
  user_class_map = login_config.lines.map do |line|
    match = line.match(/^set system login user (\S+) class (\S+)/)
    [match[1], match[2]] if match
  end.compact.to_h

  # Identify login classes assigned to non-root users
  non_root_classes = user_class_map.reject { |user, _| user == 'root' }.values.uniq

  # For each non-root login class, verify it denies the 'start shell' command
  describe 'Non-root login classes' do
    if non_root_classes.empty?
      skip 'No non-root login classes found; skipping shell access check.'
    else
      non_root_classes.each do |klass|
        describe "Login class '#{klass}'" do
          it 'should deny the "start shell" command' do
            expected_line = "set system login class #{klass} deny-commands \"start shell\""
            # Strip whitespace and match expected config line
            config_lines = login_config.lines.map(&:strip)
            expect(config_lines).to include(expected_line)
          end
        end
      end
    end
  end
end
