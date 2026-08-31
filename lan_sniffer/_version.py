"""Single source of truth for the app version.

Bump the string below when cutting a release, then push a matching `vX.Y.Z`
tag — the CI workflow takes the installer version from the tag, and the
in-app updater compares the tag against this string. If the two disagree,
the app will offer an update to a version it is already running.
"""

__version__ = "0.13.2"
__app_name__ = "LAN Signal Sniffer"
__author__ = "Omer Vered"

GITHUB_OWNER = "OmerVered1"
GITHUB_REPO = "lan-signal-sniffer"
