"""
Example usage of the libeverbloom_rs YaraRuleEngine via Python bindings.
Note: The `libeverbloom_rs` Python extension must be built and installed into the venv for this to work.
"""

from everbloom_core import libeverbloom_rs as lr

# simple rule text
RULE_TEXT = r'''
rule TestRule {
    strings:
        $a = "this_is_a_test_string"
    condition:
        $a
}
'''


def main():
    engine = lr.YaraRuleEngine()
    ok = engine.load_rules_from_string(RULE_TEXT)
    print('loaded:', ok)
    sample = b"this binary contains this_is_a_test_string inside"
    res = engine.scan_bytes(sample)
    print('scan result:', res)


if __name__ == '__main__':
    main()
