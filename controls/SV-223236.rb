control 'SV-223236' do
  title 'The Juniper SRX Services Gateway must be configured to use Junos 12.1 X46 or later to meet the minimum required version for DoD.'
  desc 'Earlier versions of Junos may have reached the end of life cycle support by the vendor. Junos 12.1X46 is not a UC APL certified version, while 12.1X46 is UC APL Certified. The SRX with Junos 12.1X46 has been NIAP certified as a firewall and VPN. Junos 12.1X46 contains a number of enhancements, particularly related to IPv6, that are relevant to the STIG.'
  desc 'check', 'Verify the version installed is Junos 12.1 X46 or later. In operational mode, type the following:

show version

If the Junos version installed is not 12.1 X46 or later, this is a finding.'
  desc 'fix', "Follow the manufacturer's instructions for upgrading the Junos version. Software updates must be from an approved site and follow approved DoD procedures and verification processes in accordance with site testing procedures."
  impact 0.5
  tag check_id: 'C-24909r513395_chk'
  tag severity: 'medium'
  tag gid: 'V-223236'
  tag rid: 'SV-223236r961863_rule'
  tag stig_id: 'JUSX-DM-000166'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-24897r513396_fix'
  tag 'documentable'
  tag legacy: ['SV-81037', 'V-66547']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Input: minimum required Junos version (e.g., '12.1X46', '15.1X49')
  minimum_version_str = input('min_junos_version')

  # Run `show version` to get the current version
  version_output = command('show version').stdout

  # Extract actual version from output
  match = version_output.match(/^Junos:\s+(\S+)/)

  describe 'Junos version line found' do
    it 'should be present in output' do
      expect(match).not_to be_nil
    end
  end

  
  if match
    current_version_str = match[1]

    # Parse both current and minimum versions into 4-element tuples [major, minor, build, patch]
    parse = lambda do |ver|
      if ver =~ /^(\d+)\.(\d+)[XR](\d+)(?:\.(\d+))?/
        [
          Regexp.last_match(1).to_i,
          Regexp.last_match(2).to_i,
          Regexp.last_match(3).to_i,
          Regexp.last_match(4) ? Regexp.last_match(4).to_i : 0
        ]
      else
        [0, 0, 0, 0]
      end
    end

    current = parse.call(current_version_str)
    minimum = parse.call(minimum_version_str)

    # Inline tuple comparison
    result = (
      current[0] > minimum[0] ||
      (current[0] == minimum[0] && current[1] > minimum[1]) ||
      (current[0] == minimum[0] && current[1] == minimum[1] && current[2] > minimum[2]) ||
      (current[0] == minimum[0] && current[1] == minimum[1] && current[2] == minimum[2] && current[3] >= minimum[3])
    )

    describe "Detected Junos version: #{current_version_str}" do
      it "should be equal to or newer than #{minimum_version_str}" do
        expect(result).to eq(true)
      end
    end
  end
end
