# Debian 11 overlay of the Canonical Ubuntu 20.04 LTS STIG baseline.
#
# All controls from the upstream profile are included as-is except the spot
# overrides below, which implement the dispositions ruled on the cfz.5 audit
# card (see its notes for the full control-status table and decision record).
#
# A control block inside include_controls REPLACES the upstream control's
# checks (verified empirically — describes do not merge), so every override
# that only *adds* to a control must faithfully reproduce the upstream check
# logic from vendor/<sha>/controls/<id>.rb alongside the addition. Keep these
# in sync when re-vendoring an updated upstream.
#
# FIPS-touching overrides carry an informational describe pointing to the
# "FIPS 140 on Debian" section of the README: Debian ships no CMVP-validated
# cryptographic modules, so these controls verify approved-algorithm
# *configuration* only. SV-238363 is deliberately kept as a permanently
# failing assertion so assessors always see that gap as a finding.
FIPS_CAVEAT = 'verifies approved-algorithm configuration only — Debian ships no CMVP-validated crypto modules, so this cannot attest FIPS-validated cryptography (see README, "FIPS 140 on Debian")'.freeze

include_controls 'Canonical_Ubuntu_20-04_LTS_STIG' do
  # SV-238216: upstream check logic reproduced verbatim; adds the Debian FIPS
  # caveat describe.
  control 'SV-238216' do
    only_if('Control not applicable - SSH is not installed within containerized Ubuntu', impact: 0.0) {
      !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
    }

    approved_macs = input('approved_openssh_server_conf')['macs']

    macs_cmd = command("/usr/sbin/sshd -T 2>/dev/null | awk '$1==\"macs\"{print $2}'")
    actual_macs = macs_cmd.stdout.strip

    describe 'OpenSSH server MACs' do
      it 'matches the approved list in exact order' do
        expect(actual_macs).to eq(approved_macs), "OpenSSH server MACs:\n\t#{actual_macs}\ndoes not match the expected value:\n\t#{approved_macs}"
      end
    end

    describe 'FIPS limitation on Debian (informational)' do
      it FIPS_CAVEAT do
        expect(true).to eq true
      end
    end
  end

  # SV-238217: upstream check logic reproduced verbatim; adds the Debian FIPS
  # caveat describe on the branch where the check actually runs.
  control 'SV-238217' do
    if input('disable_fips')
      impact 0.0
      describe 'FIPS testing has been disabled' do
        skip 'This control has been set to Not Applicable, FIPS validation has been disabled with the `disable_fips` input'
      end
    elsif %w[docker podman kubepods lxc].include?(virtualization.system)
      describe 'FIPS validation in a container must be reviewed manually' do
        skip 'FIPS validation in a container must be reviewed manually'
      end
    else
      approved = input('approved_ciphers')
      ciphers = inspec.sshd_active_config.params['ciphers']
      ciphers = ciphers.first.split(',').map(&:strip) unless ciphers.nil?

      describe 'SSH ciphers' do
        it 'should contain only approved FIPS ciphers' do
          unapproved_ciphers = ciphers.nil? ? [] : (ciphers - approved)
          missing_approved_ciphers = ciphers.nil? ? approved : (approved - ciphers)

          expect(ciphers).to_not be_nil, 'Ciphers directive missing from sshd_config'
          expect(unapproved_ciphers).to eq([]), "Non-approved ciphers present (#{unapproved_ciphers.length}): #{unapproved_ciphers.join(', ')}"
          expect(missing_approved_ciphers).to eq([]), "Approved ciphers missing (#{missing_approved_ciphers.length}): #{missing_approved_ciphers.join(', ')}"
        end
      end

      describe 'FIPS limitation on Debian (informational)' do
        it FIPS_CAVEAT do
          expect(true).to eq true
        end
      end
    end
  end

  # SV-238325: upstream check logic reproduced verbatim; adds the Debian FIPS
  # caveat describe.
  control 'SV-238325' do
    weak_pw_hash_users = inspec.shadow.where { password !~ /^[*!]{1,2}.*$|^\$6\$.*$|^$/ }.users

    describe 'All stored passwords' do
      it 'should only be hashed with the SHA512 algorithm' do
        message = "Users without SHA512 hashes:\n\t- #{weak_pw_hash_users.join("\n\t- ")}"
        expect(weak_pw_hash_users).to be_empty, message
      end
    end

    describe 'FIPS limitation on Debian (informational)' do
      it FIPS_CAVEAT do
        expect(true).to eq true
      end
    end
  end

  # SV-238363: the requirement is NIST FIPS-*validated* cryptography
  # (SRG-OS-000396 / CCI-002450 / SC-13). On Ubuntu, fips_enabled=1 implies
  # the Ubuntu Pro validated module stack; on Debian the same flag is
  # reachable with stock, uncertified builds, so the upstream proxy check
  # would pass misleadingly. Ruling (cfz.5, 2026-07-30): keep the kernel
  # check as posture evidence and ADD an assertion that always fails on
  # Debian — a deliberate standing CAT I finding so this profile never
  # presents an uncertified platform as FIPS-validated.
  control 'SV-238363' do
    only_if('This control is Not Applicable to containers', impact: 0.0) {
      !%w[docker podman kubepods lxc].include?(virtualization.system)
    }

    fips_config_file = input('fips_config_file')

    describe command("grep -i 1 #{fips_config_file}") do
      its('stdout') { should match('1') }
    end

    describe 'NIST FIPS-validated cryptographic modules' do
      it 'are available and in use on this platform' do
        expect(false).to eq(true), 'Debian provides no CMVP/NIST-validated cryptographic modules. A fips=1 kernel and approved-algorithm configuration establish a FIPS-capable posture at best; they do not constitute the FIPS-validated cryptography this requirement mandates (see README, "FIPS 140 on Debian"). This is a permanent finding on Debian — deployments operating under a FIPS mandate need a documented waiver/risk acceptance or a platform with validated modules.'
      end
    end
  end

  # SV-255912: upstream check logic reproduced verbatim; adds the Debian FIPS
  # caveat describe.
  control 'SV-255912' do
    only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
      !%w[docker podman kubepods lxc].include?(virtualization.system) || package('openssh-server').installed?
    }

    expected_kex = input('expected_kex')

    sshd_t_output = command('/usr/sbin/sshd -T 2>/dev/null').stdout
    kex_line = sshd_t_output.lines.find { |l| l.start_with?('kexalgorithms ') }
    actual_kex = kex_line.nil? ? [] : kex_line.split(/\s+/, 2)[1].to_s.strip.split(',')

    describe 'Effective SSHD KexAlgorithms' do
      subject { actual_kex }
      it 'is set and exactly matches the required FIPS-validated algorithms in order' do
        expect(subject).to eq(expected_kex), <<~MSG.chomp
          Expected KexAlgorithms to be exactly (in order):
            - #{expected_kex.join("\n  - ")}
          Actual:
            - #{actual_kex.join("\n  - ")}
        MSG
      end
    end

    describe 'FIPS limitation on Debian (informational)' do
      it FIPS_CAVEAT do
        expect(true).to eq true
      end
    end
  end

  # SV-278950: the upstream control verifies Ubuntu 20.04's identity and
  # support lifecycle (standard support -> Ubuntu Pro ESM). Rewritten for
  # Debian 11's identity and published lifecycle: Debian LTS covers bullseye
  # through 2026-08-31 (free, part of the regular archive); beyond that,
  # Extended LTS (Freexian ELTS, commercial) runs through 2031-06-30 via its
  # own apt repository — the Debian analog of the upstream's `pro status`
  # subscription branch.
  control 'SV-278950' do
    only_if('This control is Not Applicable to containers', impact: 0.0) {
      !%w[docker podman kubepods lxc].include?(virtualization.system)
    }

    describe 'Debian release identity' do
      subject { os }
      its('name') { should eq 'debian' }
      its('release') { should match(/^11(\.|$)/) }
    end

    lts_eol = Time.new(2026, 8, 31, 23, 59, 59, '+00:00')
    elts_eol = Time.new(2031, 6, 30, 23, 59, 59, '+00:00')
    now = Time.now.utc

    if now <= lts_eol
      describe 'Debian 11 support lifecycle' do
        it 'is within the Debian LTS window' do
          expect(now <= lts_eol).to be true
        end
      end
    elsif now <= elts_eol
      # Beyond free LTS; vendor support requires the commercial Freexian
      # Extended LTS repository to be configured.
      elts_sources = command('grep -rsiE "deb\\.freexian\\.com/extended-lts|extended-lts" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null')

      describe 'Debian 11 Extended LTS (Freexian) apt source' do
        subject { elts_sources.stdout.strip }
        it 'is configured, providing vendor security support beyond the Debian LTS window' do
          expect(subject).to_not be_empty, "Debian LTS for bullseye ended #{lts_eol.strftime('%Y-%m-%d')}; no Extended LTS (Freexian) apt source found, so this release no longer receives vendor security support."
        end
      end
    else
      describe 'Debian 11 support lifecycle' do
        it 'is within a vendor support window' do
          expect(now <= elts_eol).to be true, "All security support for Debian 11 (including Extended LTS) ended #{elts_eol.strftime('%Y-%m-%d')}; current date: #{now.strftime('%Y-%m-%d')}. Upgrade to a supported Debian release."
        end
      end
    end
  end
end
