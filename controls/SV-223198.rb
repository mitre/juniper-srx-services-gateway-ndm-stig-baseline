control 'SV-223198' do
  title 'For local log files, the Juniper SRX Services Gateway must allocate log storage capacity in accordance with organization-defined log record storage requirements so that the log files do not grow to a size that causes operational issues.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The amount allocated for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, and how long the logs are kept on the device. Since the Syslog is the primary audit log, the local log is not essential to keep archived for lengthy periods, thus the allocated space on the device should be low.'
  desc 'check', 'To verify the file size for the local system log is set.

[edit]
show system syslog

View the archive size setting of the local log files.

If all local log files are not set to an organizational-defined size, this is a finding.'
  desc 'fix', 'Enter the following commands in the [edit system syslog] hierarchy.

[edit system syslog] 
set file <log filename> any any archive size <file size> file <number of archives>'
  impact 0.5
  tag check_id: 'C-24871r513284_chk'
  tag severity: 'medium'
  tag gid: 'V-223198'
  tag rid: 'SV-223198r961392_rule'
  tag stig_id: 'JUSX-DM-000056'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-24859r513285_fix'
  tag 'documentable'
  tag legacy: ['SV-80967', 'V-66477']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  expected_size = input('expected_syslog_file_size', value: '10m')
  expected_files = input('expected_syslog_file_rotation', value: '3')

  # Check messages file size limit and rotation count
  describe 'Local syslog file messages configuration' do
    subject { command('show configuration system syslog file messages | display set').stdout }

    it "should set the messages log file size to #{expected_size}" do
      expect(subject).to match(/set system syslog file messages archive size #{Regexp.escape(expected_size)}/)
    end

    it "should set the number of archived messages log files to #{expected_files}" do
      expect(subject).to match(/set system syslog file messages archive files #{expected_files}/)
    end
  end
end
