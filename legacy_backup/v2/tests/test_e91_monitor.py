from src.e91_monitor import E91Monitor
def test_e91_no_attack():
    mon = E91Monitor(100, 0.15)
    assert mon.verify_channel_integrity(mon.simulate_channel("NONE"))
def test_e91_intercept():
    mon = E91Monitor(100, 0.15)
    assert not mon.verify_channel_integrity(mon.simulate_channel("INTERCEPT_RESEND"))
