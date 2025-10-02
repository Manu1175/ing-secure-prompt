from secureprompt.eval.prompt_eval import tokens_of, normalize_token

def test_tokenizer_accepts_both_brackets_and_normalizes():
    s = "Hello <EMP1_FIRST> [EMP1_LAST] <EMP1_EMAIL1>"
    toks = {normalize_token(t) for t in tokens_of(s)}
    assert "EMP1_FIRST" in toks
    assert "EMP1_LAST" in toks
    assert "EMP1_EMAIL" in toks  # trailing digit trimmed
