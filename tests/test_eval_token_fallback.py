from secureprompt.eval.prompt_eval import _fallback_tokenize_from_scrubbed, tokens_of, normalize_token

def test_scrub_tag_to_token():
    s = "Hello C4::EMAIL::deadbeef10 and C3::IBAN::cafebabe42"
    eval_s = _fallback_tokenize_from_scrubbed(s)
    toks = {normalize_token(t) for t in tokens_of(eval_s)}
    assert "EMAIL" in toks
    assert "IBAN" in toks
