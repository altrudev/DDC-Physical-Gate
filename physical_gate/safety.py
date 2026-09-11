"""No physical execution transport is included. Explicitly deny real endpoints."""
class RealHardwareUnavailable(RuntimeError): pass

def connect_real_hardware(*args, **kwargs):
    raise RealHardwareUnavailable('Real hardware is not supported by this research reference')
