from secureprompt.scrub.pipeline import scrub_text


def test_scrub_replaces_values_with_policy_actions():
    text = "Email a@b.com; Card 4111 1111 1111 1111"
    out = scrub_text(text, c_level="C3")

    assert out["scrubbed"] != text

    entities = {entity["label"]: entity for entity in out["entities"]}

    email = entities["EMAIL"]
    pan = entities["PAN"]

    assert email["identifier"].startswith("C3::EMAIL::")
    assert email["mask_preview"].count("*") == len("a@b.com")

    assert pan["identifier"].startswith("C3::PAN::")
    assert "mask_preview" not in pan

    assert "C3::PAN::" in out["scrubbed"]
