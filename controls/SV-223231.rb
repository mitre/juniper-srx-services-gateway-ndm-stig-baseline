control 'SV-223231' do
  title 'The Juniper SRX Services Gateway must terminate a device management session after 10 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session. Quickly terminating an idle session also frees up resources. 

This requirement does not mean that the device terminates all sessions or network access; it only ends the inactive session.

User accounts, including the account of last resort must be assigned to a login class. Configure all login classes with an idle timeout value. Pre-defined classes do not support configurations, therefore should not be used for DoD implementations. The root account cannot be assigned to a login-class which is why it is critical that this account be secured in accordance with DoD policy.'
  desc 'check', 'Verify idle-timeout is set for 10 minutes.

[edit]
show system login

If a timeout value of 10 or less is not set for each class, this is a finding.'
  desc 'fix', 'Configure all login classes with an idle timeout value. 

[edit]
set system login-class <class name> idle-timeout 10

All users must be set to a login-class; however, to ensure that the CLI is set to a default timeout value, enter the following in operational mode: 

set cli idle-timeout 10'
  impact 0.5
  tag check_id: 'C-24904r513380_chk'
  tag severity: 'medium'
  tag gid: 'V-223231'
  tag rid: 'SV-223231r961068_rule'
  tag stig_id: 'JUSX-DM-000156'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-24892r513381_fix'
  tag 'documentable'
  tag legacy: ['SV-81027', 'V-66537']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']


  # How to see which users are assigned to which classes
  # show configuration system login | display set | match class

  # To Verify idle-timeout in Junos 22.x (correct way):
  # show configuration | display set | match "idle-timeout"


  # Get all user-related configuration lines
  config_lines = command('show configuration system login | display set | match "^set system login user"').stdout.lines.map(&:strip)

  # Group configuration lines by username
  users = {}
  config_lines.each do |line|
    if line =~ /^set system login user (\S+)/
      user = Regexp.last_match(1)
      users[user] ||= []
      users[user] << line
    end
  end

  used_classes = Set.new

  # Check each user has a class assigned
  users.each do |user, lines|
    class_line = lines.find { |l| l.include?('class ') }

    describe "User #{user}" do
      it 'should have a login class assigned' do
        expect(class_line).not_to be_nil, "User '#{user}' is missing a login class assignment."
      end
    end

    if class_line
      class_name = class_line.match(/class\s+(\S+)/)&.captures&.first
      used_classes << class_name if class_name
    end
  end

  # Check each used class has idle-timeout set to 600
  used_classes.each do |klass|
    timeout_line = command("show configuration system login class #{klass} | display set | match idle-timeout").stdout.strip

    describe "Login class '#{klass}' idle-timeout setting" do
      it 'should be set to 600 seconds' do
        expect(timeout_line).to match(/^set system login class #{klass} idle-timeout 600$/),
          "Login class '#{klass}' is missing 'idle-timeout 600' configuration. Output: '#{timeout_line}'"
      end
    end
  end
end
