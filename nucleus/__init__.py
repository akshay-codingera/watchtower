""" nucleus/ (nucleus package / folder)
    WATCHTOWER  foundation layer

    Provides   shared types ( ), configuration , constants , exceptions , and telemetry to every other module in the platform.

    Import pattern used throughout the codebase:
    from nucleus.constants import LogFormat, DeviceType, SEVERITY_NAMES
    from nucleus.record    import LogRecord
    from nucleus.config    import cfg
    from nucleus.telemetry import metrics
    from nucleus.exceptions import ParseError, ValidationError

"""