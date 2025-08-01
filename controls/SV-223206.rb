control 'SV-223206' do
  title 'The Juniper SRX Services Gateway must be configured to use an authentication server to centrally manage authentication and logon settings for remote and nonlocal access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is a particularly important protection against the insider threat. Audit records for administrator accounts access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device. 

The Juniper SRX supports three methods of user authentication: local password authentication, Remote Authentication Dial-In User Service (RADIUS), and Terminal Access Controller Access Control System Plus (TACACS+). RADIUS and TACACS+ are remote access methods used for management of the Juniper SRX. The local password method will be configured for use only for the account of last resort.

To completely set up AAA authentication, create a user template account (the default name is remote) and specify a system authentication server and an authentication order. See CCI-000213 for more details. The remote user template is not a logon account. Once the AAA server option is configured, any remote or nonlocal access attempts are redirected to the AAA server. Since individual user accounts are not defined on the SRX, the authentication server must be used to manage individual account settings."
  desc 'check', 'Verify the Juniper SRX is configured to support the use of AAA services to centrally manage user authentication and logon settings. 

From the CLI operational mode enter: 
show system radius-server 
or 
show system tacplus-server

If the Juniper SRX has not been configured to support the use RADIUS and/or TACACS+ servers to centrally manage authentication and logon settings for remote and nonlocal access, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to support the use of AAA services to centrally manage user authentication and logon settings. To completely set up AAA authentication, use a user template account (the default name is remote) and specify a system authentication server and an authentication order. 

[edit]
set system tacplus-server address <server ipaddress> port 1812 secret <shared secret> 

or 

[edit]
set system radius-server address <server ipaddress> port 1812 secret <shared secret> 

Note: DOD policy is that redundant AAA servers are required to mitigate the risk of a failure of the primary AAA device. Also see CCI-000213 for further details.'
  impact 0.5
  tag check_id: 'C-24879r513305_chk'
  tag severity: 'medium'
  tag gid: 'V-223206'
  tag rid: 'SV-223206r997567_rule'
  tag stig_id: 'JUSX-DM-000095'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-24867r997566_fix'
  tag 'documentable'
  tag legacy: ['SV-80979', 'V-66489']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-003627', 'CCI-003628', 'CCI-003831', 'CCI-004046', 'CCI-004047', 'CCI-004058', 'CCI-004059', 'CCI-004060', 'CCI-004061', 'CCI-004063', 'CCI-004064', 'CCI-004065', 'CCI-004068']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AC-2 (3) (a)', 'AC-2 (3) (b)', 'AU-9 b', 'IA-2 (6) (a)', 'IA-2 (6) (b)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (e)', 'IA-5 (1) (f)', 'IA-5 (1) (g)', 'IA-5 (2) (b) (2)']


  # Input for expected external syslog host
  aaa_servers_configured = input('aaa_servers_configured')

   # If we have AAA servers configured, we can check the authentication order and user template
  if aaa_servers_configured && !aaa_servers_configured.empty?
    # Run command to get all system authentication-related settings
    auth_config = command('show configuration system | display set | match "authentication"').stdout

    describe 'AAA Authentication configuration presence' do
      it 'should not be empty' do
        expect(auth_config).not_to be_empty
      end
    end

    # Check if an authentication-order is defined and includes radius or tacplus
    describe 'Authentication order includes AAA service' do
      it 'should include radius or tacplus in the configured authentication order' do
        expect(auth_config).to match(/set system authentication-order .*radius|tacplus/)
      end
    end

    # Check if at least one AAA server (radius or tacplus) is configured
    auth_servers = command('show configuration system | display set').stdout

    describe 'Authentication server configuration' do
      it 'should include RADIUS or TACACS+ configuration' do
        expect(auth_servers).to match(/radius-server|tacplus-server/)
      end
    end  

    # Check if a remote template user is defined
    user_template = command('show configuration system login user remote').stdout

    describe 'Remote user template exists' do
      it 'should define a user "remote" with a class' do
        expect(user_template).to match(/class\s+\S+/)
      end
    end  
  else
    # If no AAA servers are configured, skip the control and set impact to 0.0
    impact 0.0
    describe 'AAA Server Configuration' do
      skip 'Skipped because aaa_servers_configured input is not set.'
    end
  end
end
