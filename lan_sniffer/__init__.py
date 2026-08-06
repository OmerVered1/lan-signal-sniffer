# READ-ONLY PACKAGE
"""LAN Signal Sniffer — passive capture and decode of lab-instrument traffic.

This package is passive by construction. It observes packets that the host's
network stack has already seen; it never transmits. No module here may open a
connection to a monitored device: many lab instruments (the Setaram C80 among
them) accept a single TCP client at a time, so connecting would steal the port
from the vendor software and could abort a running experiment or an unattended
temperature profile.

See `lan_sniffer.capture.capture` for the one place that touches a network
handle, and note that it is opened for capture only.
"""

__version__ = "0.1.0"
