control 'SV-229014' do
  title 'The Juniper SRX Services Gateway must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc 'Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types.

The Juniper SRX can be configured to limit login times or to logout users after a certain time period if desired by the organization. These setting are configured as options on the login class to which they apply.'
  desc 'check', 'If the organization does not have a requirement for triggered, automated logout, this is not a finding.

Obtain a list of organization-defined triggered, automated requirements that are required for the Juniper SRX. 

To verify configuration of special user access controls.

[edit]
show system login

View time-based or other triggers which are configured to control automated logout.

If the organization has documented requirements for triggered, automated termination and they are not configured, this is a finding.'
  desc 'fix', 'To configure user access on specific days of the week for a specified duration, include the allowed-days, access-start, and access-end statements. The following is an example of a configuration for a class which would automatically log out users. Consult the Juniper SRX documentation for other options.

[edit system login]
class class-name allowed-days [ days-of-the-week ];
class class-name access-start HH:MM;
class class-name access-end HH:MM;'
  impact 0.5
  tag check_id: 'C-31329r518218_chk'
  tag severity: 'medium'
  tag gid: 'V-229014'
  tag rid: 'SV-229014r961863_rule'
  tag stig_id: 'JUSX-DM-000007'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31306r518219_fix'
  tag 'documentable'
  tag legacy: ['SV-80947', 'V-66457']
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
