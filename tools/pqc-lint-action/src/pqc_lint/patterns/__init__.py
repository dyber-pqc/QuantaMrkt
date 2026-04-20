"""Per-language pattern matchers."""

from pqc_lint.patterns.base import PatternMatcher, PatternSpec
from pqc_lint.patterns.c_cpp import CCppMatcher
from pqc_lint.patterns.go import GoMatcher
from pqc_lint.patterns.java import JavaMatcher
from pqc_lint.patterns.javascript import JavaScriptMatcher
from pqc_lint.patterns.python import PythonMatcher
from pqc_lint.patterns.rust import RustMatcher

ALL_MATCHERS: list[PatternMatcher] = [
    PythonMatcher(),
    JavaScriptMatcher(),
    GoMatcher(),
    RustMatcher(),
    JavaMatcher(),
    CCppMatcher(),
]

MATCHERS_BY_LANGUAGE: dict[str, PatternMatcher] = {m.language: m for m in ALL_MATCHERS}

__all__ = [
    "PatternMatcher",
    "PatternSpec",
    "ALL_MATCHERS",
    "MATCHERS_BY_LANGUAGE",
    "PythonMatcher",
    "JavaScriptMatcher",
    "GoMatcher",
    "RustMatcher",
    "JavaMatcher",
    "CCppMatcher",
]
