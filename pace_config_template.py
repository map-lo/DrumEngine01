"""
PACE Eden SDK Configuration for AAX Signing

This file contains your PACE credentials and plugin identifiers.
DO NOT commit this file to version control (it's in .gitignore).

To get these credentials:
1. Sign up as AAX Developer at https://developer.avid.com/aax/
2. Request signing tools from audiosdk@avid.com with subject "PACE Eden Signing Tools Request"
3. PACE Anti-Piracy will contact you with your credentials
4. Access the iLok Developer portal to generate your wcguid

For more info, see: modules/JUCE/docs/JUCE AAX Format.md
"""

# Path to wraptool executable (from PACE Eden SDK)
# Example: "/Applications/PACEAntiPiracy/Eden/Fusion/Current/bin/wraptool"
WRAPTOOL_PATH = "/path/to/wraptool"

# PACE iLok account credentials
ACCOUNT_ID = "your-ilok-account-id"
ACCOUNT_PASSWORD = "your-ilok-password"

# Wrap Configuration GUID (generated from iLok Developer portal)
# This is the same for both dev and release builds
WCGUID = "your-wrap-configuration-guid"

# Signing Identity ID (from iLok Developer portal)
# This is typically the same for both dev and release builds
SIGNID = "your-signing-identity-id"

# Optional: Different signing configurations for dev vs release
# Leave as None to use the same credentials for both
DEV_SIGNID = None  # If different from SIGNID
RELEASE_SIGNID = None  # If different from SIGNID
