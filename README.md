# debian-11-stig-baseline

STIG-ready InSpec validation baseline for Debian 11 (bullseye).

There is no DISA STIG for Debian. This profile is an overlay of the
[Canonical Ubuntu 20.04 LTS STIG baseline](https://github.com/mitre/canonical-ubuntu-20.04-lts-stig-baseline)
maintained by the MITRE SAF team, chosen because Ubuntu 20.04's component set
(OpenSSL 1.1.1, systemd/PAM era) is the closest STIG-covered match to
Debian 11. Ubuntu-specific checks are adapted or marked not applicable for
Debian in `controls/overlay.rb`.

This is **not** DISA-published content. It is a STIG-ready baseline mapped to
the same GPOS SRG requirements the Ubuntu STIG is derived from.

## Running

```sh
inspec exec . -t ssh://user@debian11-host --input-file inputs.yml --reporter cli json:results.json
```

## Overlay structure

- `inspec.yml` — profile metadata; declares the pinned upstream dependency
- `controls/overlay.rb` — `include_controls` of the upstream profile plus
  per-control Debian overrides
