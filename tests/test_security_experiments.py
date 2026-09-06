from src.security_experiments import SecurityExperiments
def test_security_experiments():
    exp = SecurityExperiments()
    rep = exp.run_comparison()
    assert len(rep) >= 6
