# Debian 11 overlay of the Canonical Ubuntu 20.04 LTS STIG baseline.
#
# All controls from the upstream profile are included as-is. Debian-specific
# adjustments (package names, file paths, N/A determinations for Ubuntu-only
# tooling) are made by overriding individual controls inside this block.
include_controls 'Canonical_Ubuntu_20-04_LTS_STIG'
