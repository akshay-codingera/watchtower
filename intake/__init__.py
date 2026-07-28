"""
intake/
=======
WATCHTOWER receiving layer.

Everything that touches a raw socket lives here. Nothing in this
package knows how to parse a syslog message — that is pipeline's job.
intake's only responsibilities are: accept bytes off the wire, wrap
them in a minimal LogRecord via LogRecord.from_raw(), rate-limit by
source IP, and hand the record to the conduit queue for the pipeline
(or, until pipeline exists, the ingest worker in core.py) to pick up.

Import pattern used throughout the codebase:
    from intake.conduit       import Conduit, ConduitClosed
    from intake.ratelimiter   import RateLimiter
    from intake.listener      import UDPListener
    from intake.tls_listener  import TCPListener
    from intake.framer        import TCPFramer
    from intake.intake_metrics import IntakeMetrics
"""