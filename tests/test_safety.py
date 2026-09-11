import pytest
from physical_gate.safety import connect_real_hardware, RealHardwareUnavailable

def test_no_real_hardware():
    with pytest.raises(RealHardwareUnavailable): connect_real_hardware('ros2://robot')
