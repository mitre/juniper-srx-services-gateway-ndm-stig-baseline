control 'SV-223204' do
  title 'The Juniper SRX Services Gateway must have the number of rollbacks set to 5 or more.'
  desc 'Backup of the configuration files allows recovery in case of corruption, misconfiguration, or catastrophic failure. The maximum number of rollbacks for the SRX is 50 while the default is 5 which is recommended as a best practice. Increasing this backup configuration number will result in increased disk usage and increase the number of files to manage. Organizations should not set the value to zero.'
  desc 'check', 'To view the current setting for maximum number of rollbacks enter the following command.

[edit]
show system max-configuration-rollbacks

If the number of back up configurations is not set to an organization-defined value which is 5 or more, this is a finding.'
  desc 'fix', 'To configure number of backup configurations to be stored in the configuration partition enter the following command at the configuration hierarchy.

[edit]
set system max-configuration-rollbacks <organization-defined number>'
  impact 0.3
  tag check_id: 'C-24877r513299_chk'
  tag severity: 'low'
  tag gid: 'V-223204'
  tag rid: 'SV-223204r961863_rule'
  tag stig_id: 'JUSX-DM-000087'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-24865r513300_fix'
  tag 'documentable'
  tag legacy: ['SV-81085', 'V-66595']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Load the minimum required rollback count from InSpec inputs
  min_rollbacks = input('min_rollback_configs', value: 10)

  # Run the command to get the rollback configuration
  cmd = command('show configuration system max-configuration-rollbacks')
  output = cmd.stdout.strip

  # Validate that the command executed successfully
  describe 'Max configuration rollbacks command' do
    it 'should execute successfully' do
      expect(cmd.exit_status).to eq 0
    end
  end

  # If the setting is not configured (empty output), assert non-compliance using `be_empty`
  describe 'max-configuration-rollbacks setting presence' do
    it 'should be explicitly configured' do
      expect(output).not_to be_empty
    end
  end

  # Only run this test if the setting was present (avoid comparing nil)
  unless output.empty?
    rollback_count = output.to_i

    describe 'Configured rollback count value' do
      it "should be greater than or equal to #{min_rollbacks}" do
        expect(rollback_count).to be >= min_rollbacks
      end
    end
  end
  # # Run the command to get the configured max rollback count
  # cmd = command('show configuration system max-configuration-rollbacks')

  # describe 'Max configuration rollbacks setting' do
  #   it 'should be present in the configuration' do
  #     expect(cmd.exit_status).to eq 0
  #     expect(cmd.stdout).not_to be_empty
  #   end
  # end

  # if cmd.stdout.strip.empty?
  #   # If not explicitly set, Junos defaults to 0 — treat as non-compliant
  #   # describe 'Rollback count' do
  #   #   it 'should be explicitly configured' do
  #   #     fail 'max-configuration-rollbacks is not set; default is 0, which is non-compliant.'
  #   #   end
  #   # end
  #   describe 'max-configuration-rollbacks' do
  #     it "should be explicitly set to a value >= #{min_rollbacks}" do
  #       raise_inspec_error 'max-configuration-rollbacks is not set; default is 0, which is non-compliant.'
  #     end
  #   end
  # else
  #   rollback_count = cmd.stdout.strip.to_i

  #   describe rollback_count do
  #     it { should be >= min_rollbacks }
  #   end
  # end  
end
