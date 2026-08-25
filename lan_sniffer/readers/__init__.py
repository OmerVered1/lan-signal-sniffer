"""Active readers, for instruments that publish data on a request.

Everything else in this package is passive: it watches traffic and never
transmits, because the instruments it was built for accept a single client and
connecting would take it away from the software running the experiment.

A Modbus slave is a different thing. It exists to be polled by a master and
normally accepts several, so reading it is what it is for. The passive rule is
kept where its reason applies and deliberately not extended here.
"""
