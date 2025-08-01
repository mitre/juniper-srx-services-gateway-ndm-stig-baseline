control 'SV-229025' do
  title 'The Juniper SRX Services Gateway must be configured to use a centralized authentication server to authenticate privileged users for remote and nonlocal access for device management.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is a particularly important protection against the insider threat. Audit records for administrator accounts access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

The Juniper SRX supports three methods of user authentication: local password authentication, Remote Authentication Dial-In User Service (RADIUS), and Terminal Access Controller Access Control System Plus (TACACS+). RADIUS and TACACS+ are remote access methods used for management of the Juniper SRX. The local password method will be configured for use only for the account of last resort; however, it will not be used for remote and nonlocal access or this will result in a CAT 1 finding (CCI-000765).

This requirement references identification and authentication and does not prevent the configuration of privileges using the remote template account (CCI-000213)."
  desc 'check', 'Verify the Juniper SRX is configured to forward logon requests to a RADIUS or TACACS+. 

From the CLI operational mode enter: 
show system radius-server 
or 
show system tacplus-server

If the Juniper SRX is not configured to use at least one RADIUS or TACACS+ server, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to forward logon requests to a RADIUS or TACACS+. Remove local users configured on the device (CCI-000213) so the AAA server cannot default to using a local account. 

[edit]
set system tacplus-server address <server ipaddress> port 1812 secret <shared secret> 

or 

[edit]
set system radius-server address <server ipaddress> port 1812 secret <shared secret> 

Note: DOD policy is that redundant AAA servers are required to mitigate the risk of a failure of the primary AAA device.'
  impact 0.7
  tag check_id: 'C-31340r518251_chk'
  tag severity: 'high'
  tag gid: 'V-229025'
  tag rid: 'SV-229025r1015761_rule'
  tag stig_id: 'JUSX-DM-000097'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31317r997568_fix'
  tag 'documentable'
  tag legacy: ['SV-80939', 'V-66449']
  tag cci: ['CCI-000366', 'CCI-000015', 'CCI-002132']
  tag nist: ['CM-6 b', 'AC-2 (1)', 'AC-2 (4)']

  use_tacacs_or_radius = input('use_tacacs_or_radius')

  if !use_tacacs_or_radius
    impact 0.0
    describe 'Centralized authentication check' do
      skip 'Control not applicable because use_tacacs_or_radius (TACACS+, RADIUS) input is set to false.'
    end
  else
    describe.one do
      describe command('show configuration system tacplus-server | display set') do
        its('stdout') { should match(/set system tacplus-server address #{Regexp.escape(input('aaa_server_address'))} port 1812 secret #{Regexp.escape(input('aaa_shared_secret'))}/) }
      end

      describe command('show configuration system radius-server | display set') do
        its('stdout') { should match(/set system radius-server address #{Regexp.escape(input('aaa_server_address'))} port 1812 secret #{Regexp.escape(input('aaa_shared_secret'))}/) }
      end
    end
  end
end
