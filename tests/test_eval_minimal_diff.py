from secureprompt.eval.prompt_eval import minimal_diff

def test_minimal_diff_marks_changes():
    a = "Hello [NAME], send 50 EUR."
    b = "Hello [NAME], send 60 EUR today."
    d = minimal_diff(a, b, max_chars=1000)
    # Should include an insertion marker for '60 EUR today.' vs '50 EUR.'
    assert "[+" in d or "+]" in d
    assert "[-" in d or "-]" in d
