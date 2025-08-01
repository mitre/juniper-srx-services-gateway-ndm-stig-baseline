control 'SV-229021' do
  title 'The Juniper SRX Services Gateway must allow only the information system security manager (ISSM) (or administrators/roles appointed by the ISSM) to select which auditable events are to be generated and forwarded to the syslog and/or local logs.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

The primary audit log permissions are set on the Syslog server, not the Juniper SRX. However, it is a best practice to also keep local logs for troubleshooting and backup. These logs are subject to access control requirements.

This configuration is a two-step process. Part of the configuration must be performed on the AAA server. After a user successfully logs on, the AAA sever passes the template or role of the user to the Juniper SRX. Each AAA template or role is mapped to a login class on the Juniper SRX. 

On the Juniper SRX, the class name, audit-admin, is recommended as a best practice because it follows the naming convention used in NIAP testing and is self-documenting."
  desc 'check', 'Verify only the ISSM (or administrators or roles appointed by the ISSM) have permission to configure and control audit events.

[edit]
show system login class
show system login

View permissions for the audit-admin class (audit-admin is an example class name; local policy may dictate another name). View class assignment for all users and template users configured on the Juniper SRX.

If user templates or users are other than the ISSM (or administrators or roles appointed by the ISSM) have permission to select which auditable events are to be audited, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to allow only the ISSM user account (or administrators/roles appointed by the ISSM) to select which auditable events are to be audited. To ensure this is the case, each ISSM-appointed role on the AAA must be configured for least privilege using the following stanzas for each role.

For audit-admin role:

[edit]
set system login class audit-admin permissions [ security trace maintenance ]
set system login class audit-admin allow-commands "^clear (log|security log)" 
set system login class audit-admin deny-commands "^clear (security alarms|system login lockout)|^file (copy|delete|rename)|^request (security|system set-encryption-key)|^rollback|^set date|^show security (alarms|dynamic-policies|match-policies|policies)|^start shell"
set system login class audit-admin security-role audit-administrator 
set system login user audit-officer class audit-admin 

For the crypto admin role:

[edit]
set system login class crypto-admin permissions [ admin-control configure maintenance security-control system-control trace ]
set system login class crypto-admin allow-commands "^request system set-encryption-key" 
set system login class crypto-admin deny-commands "^clear (log|security alarms|security log|system login lockout)|^file (copy|delete|rename)|^rollback|^set date|^show security (alarms|dynamic-policies|match-policies|policies)|^start shell"
set system login class crypto-admin allow-configuration-regexps "security (ike|ipsec) (policy|proposal)" "security ipsec ^vpn$ .* manual (authentication|encryption|protocol|spi)" "system fips self-test after-key-generation" 
set system login class crypto-admin security-role crypto-administrator 

For the security-admin role:

[edit]
set system login class security-admin permissions all 
set system login class security-admin deny-commands "^clear (log|security log)|^(clear|show) security alarms alarm-type idp|^request (security|system set-encryption-key)|^rollback|^start shell"
set system login class security-admin deny-configuration-regexps "security alarms potential-violation idp" "security (ike|ipsec) (policy|proposal)" "security ipsec ^vpn$ .* manual (authentication| encryption|protocol|spi)" "security log cache" "security log exclude .* event-id IDP_.*" "system fips self-test after-key- generation" 
set system login class security-admin security-role security-administrator 

For the ids-admin role:

[edit]
set system login class ids-admin permissions [ configure maintenance security-control trace ]
set system login class ids-admin allow-configuration-regexps "security alarms potential-violation idp" "security log exclude .* event-id IDP_.*" 
set system login class ids-admin deny-commands "^clear log|^(clear|show) security alarms (alarm-id|all|newer-than|older- than|process|severity)|^(clear|show) security alarms alarm-type (authentication|cryptographic-self-test|decryption-failures|encryption-failures| ike-phase1-failures|ike-phase2-failures|key-generation-self-test| non-cryptographic-self-test|policy|replay-attacks)|^file (copy|delete|rename)|^request (security|system set-encryption-key)|^rollback|^set date|^show security (dynamic-policies|match-policies|policies)|^start shell"
set system login class ids-admin deny-configuration-regexps "security alarms potential-violation (authentication|cryptographic-self-test|decryption-failures|encryption-failures|ike-phase1-failures|ike-phase2-failures|key-generation-self-test|non-cryptographic-self-test|policy|replay-attacks)" 
set system login class ids-admin security-role ids-admin 

For the crypto-officer class:

[edit]
set system login user crypto-officer class crypto-admin 
set system login user security-officer class security-admin
set system login user ids-officer class ids-admin'
  impact 0.3
  tag check_id: 'C-31336r518239_chk'
  tag severity: 'low'
  tag gid: 'V-229021'
  tag rid: 'SV-229021r1015758_rule'
  tag stig_id: 'JUSX-DM-000039'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31313r518240_fix'
  tag 'documentable'
  tag legacy: ['SV-81047', 'V-66557']
  tag cci: ['CCI-000366', 'CCI-000015', 'CCI-001684']
  tag nist: ['CM-6 b', 'AC-2 (1)', 'AC-2 (4)']

  # List of authorized user accounts or classes (roles) permitted to modify audit config
  authorized_admins = input('authorized_audit_admins')

  # Retrieve the full list of configured users and their permissions
  cmd = command('show configuration system login | display set')
  user_config = cmd.stdout

  describe 'System login configuration retrieval' do
    it 'should succeed' do
      expect(cmd.exit_status).to eq(0)
    end
  end

  # Extract all users and their associated classes (permissions)
  user_class_map = user_config.lines.grep(/^set system login user/).map do |line|
    match = line.match(/^set system login user (\S+) class (\S+)/)
    match ? [match[1], match[2]] : nil
  end.compact.to_h

  describe 'User roles authorized to manage audit configuration' do
    # Ensure only authorized roles or users exist with access to configure auditing
    user_class_map.each do |user, user_class|
      it "user #{user} with class #{user_class} must be authorized" do
        expect(authorized_admins).to include(user) | include(user_class)
      end
    end
  end  
end
