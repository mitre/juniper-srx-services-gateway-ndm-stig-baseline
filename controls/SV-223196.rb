control 'SV-223196' do
  title 'The Juniper SRX Services Gateway must generate log records when concurrent logons from different workstations occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device generates a log when login events occur.

[edit]
show system syslog

host <syslog server address> {
  any any;
  source-address <device address>;
}

If an external syslog host is not configured to log, or configured for facility any severity any, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host to log facility any and severity info or any. There are multiple ways to accomplish this, the following is an example.

[edit system syslog]
set host <syslog server address> any any'
  impact 0.3
  tag check_id: 'C-24869r513278_chk'
  tag severity: 'low'
  tag gid: 'V-223196'
  tag rid: 'SV-223196r961833_rule'
  tag stig_id: 'JUSX-DM-000046'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-24857r513279_fix'
  tag 'documentable'
  tag legacy: ['SV-81059', 'V-66569']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # Notes
  # This control only detects potential concurrency by multiple login entries with different source IPs.
  # Junos SRX does not track active sessions per user natively in logs for concurrency checks.
  # For real-time or more precise session concurrency detection, use external tools (SIEM, NAC, AAA servers).

  # Sample log extraction and check for multiple login sources per user
  # This is a basic heuristic scan for multiple successful login events for the same user from different IPs.
  describe 'Check for concurrent logons from different IPs for same user' do
    subject { command("show log messages | match 'Accepted password for'").stdout.lines }

    it 'should not have multiple concurrent login entries from different IPs for the same user' do
      user_ips = {}
      subject.each do |line|
        # Extract user and IP from log line e.g.
        # sshd[1234]: Accepted password for admin from 192.0.2.10 port 514 ssh2
        if line =~ /Accepted password for (\S+) from ([\d\.]+)/
          user = Regexp.last_match(1)
          ip = Regexp.last_match(2)
          user_ips[user] ||= Set.new
          user_ips[user] << ip
        end
      end

      # Fail if any user has logins from more than one IP address (basic concurrent login indicator)
      user_ips.each do |user, ips|
        expect(ips.size).to be <= 1, "User #{user} has concurrent logins from multiple IPs: #{ips.to_a.join(', ')}"
      end
    end
  end
end
