from src.e91_monitor import E91Monitor
def test_e91_no_attack():
    mon = E91Monitor(100, 0.15)
    assert mon.verify_channel_integrity(mon.measure_disturbance("NONE")["error_rate"])
def test_e91_intercept():
    mon = E91Monitor(1000, 0.15)
    assert not mon.verify_channel_integrity(mon.measure_disturbance("INTERCEPT_RESEND")["error_rate"])
