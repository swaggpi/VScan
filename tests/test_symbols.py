"""Symbol <-> advisory matching: the strict path must not fire on English words."""

from __future__ import annotations

import pytest

from scanner.correlate.symbols import (
    _match_called_symbol,
    _named_functions,
    advisory_matches_called_symbol,
)

JINJA_SUMMARIES = [
    "Jinja2 sandbox escape via string formatting",
    "Jinja has a sandbox breakout through indirect reference to format method",
    "Jinja2 vulnerable to sandbox breakout through attr filter selecting format method",
]



@pytest.mark.parametrize("text", JINJA_SUMMARIES)
def test_jinja_escape_not_confirmed_by_english_word(text):
    assert not advisory_matches_called_symbol(["jinja2.escape"], text)


def test_yaml_full_load_still_confirmed_without_function_form():
    bare_only = "Improper Input Validation in PyYAML via full_load"
    assert _named_functions(bare_only) == []
    assert advisory_matches_called_symbol(["yaml.full_load"], bare_only)


def test_underscore_or_digit_token_is_distinctive():
    assert advisory_matches_called_symbol(["os.load_module"], "bug in load_module here")
    assert advisory_matches_called_symbol(["base64.b64decode"], "flaw in b64decode handling")


@pytest.mark.parametrize(
    "text",
    ["The jsonify() helper is unsafe", "unsafe use of flask.jsonify in views"],
)
def test_function_form_fires(text):
    assert advisory_matches_called_symbol(["flask.jsonify"], text)
    # Without function form the same plain word does not fire.
    assert not advisory_matches_called_symbol(["flask.jsonify"], "jsonify output is wrong")


def test_generic_word_in_function_form_still_does_not_fire_bare():
    # `escape` is in _GENERIC_TOKENS: it never fires bare, even as `escape()`.
    assert not advisory_matches_called_symbol(["jinja2.escape"], "The escape() helper is unsafe")


def test_full_dotted_and_two_component_tokens_unchanged():
    assert advisory_matches_called_symbol(["jinja2.escape"], "calls jinja2.escape")
    assert advisory_matches_called_symbol(["PIL.Image.open"], "bug in Image.open parsing")
    assert advisory_matches_called_symbol(["yaml.load"], "yaml.load is unsafe")


def test_new_generic_words_never_fire_bare():
    for word in ("render", "filter", "format", "select", "sanitize", "quote",
                 "unquote", "encode", "decode", "join", "split", "resolve",
                 "execute", "sandbox", "verify", "validate", "serialize",
                 "deserialize"):
        assert not advisory_matches_called_symbol(
            [f"pkg.{word}"], f"the {word}() issue and pkg-less {word} text"
        )


def test_generous_path_unchanged():
    # Generous still matches the bare word (it only withholds "safe" verdicts).
    hit = _match_called_symbol(["jinja2.escape"], JINJA_SUMMARIES[0].lower(), strict=False)
    assert hit == ("jinja2.escape", "escape")
    assert _match_called_symbol(["yaml.full_load"], "uses full_load", strict=False) is not None
    assert _match_called_symbol(["yaml.load"], "uses load somewhere", strict=False) is not None
