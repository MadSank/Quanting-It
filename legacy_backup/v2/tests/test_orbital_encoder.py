from src.orbital_encoder import OrbitalEncoder
def test_collisions():
    cols = OrbitalEncoder.find_collisions(["01", "10"], 2)
    assert len(cols) > 0
def test_efficiency():
    eff = OrbitalEncoder.encoding_efficiency(2, 2)
    assert eff["information_loss"]
