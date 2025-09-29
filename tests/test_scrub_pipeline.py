from secureprompt.scrub.pipeline import scrub_text

def test_scrub_replaces_values_with_ids():
    text = "Email a@b.com; Card 4111 1111 1111 1111"
    out = scrub_text(text, c_level="C3")
    assert out["scrubbed"] != text
    assert "C3::EMAIL::" in out["scrubbed"]
    assert "C3::PAN::" in out["scrubbed"]
