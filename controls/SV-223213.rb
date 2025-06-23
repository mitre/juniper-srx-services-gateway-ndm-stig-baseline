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

  # Validates Two Key Conditions:
  #   Only the root user is assigned class super-user
  #   All other user classes explicitly use:
  #     deny-commands "(start shell)" — to prevent UNIX shell access even if permission levels are high

  # Retrieve all user configurations
  user_config = command('show configuration system login | display set').stdout
  super_users = user_config.lines.select { |line| line =~ /^set system login user (\S+) class super-user/ }
  super_user_names = super_users.map { |line| line.match(/^set system login user (\S+) class super-user/)[1] }

  describe 'Super-user accounts' do
    it 'should only include root' do
      expect(super_user_names).to eq(['root'])
    end
  end

  # Retrieve all login class configurations that deny "start shell"
  class_config = command('show configuration system login class | display set').stdout
  deny_shell_classes = class_config.lines.select { |line| line.include?('deny-commands "(start shell)"') }
  deny_class_names = deny_shell_classes.map { |line| line.match(/^set system login class (\S+) deny-commands/)[1] }.uniq

  # Get all login class names assigned to non-root users
  non_root_user_classes = user_config.lines
    .select { |line| line =~ /^set system login user (\S+) class (\S+)/ && $1 != 'root' }
    .map { |line| line.match(/^set system login user \S+ class (\S+)/)[1] }.uniq

  describe 'Non-root login classes' do
    it 'should deny the "start shell" command explicitly' do
      expect(deny_class_names.sort).to include(*non_root_user_classes.sort)
    end
  end
end
