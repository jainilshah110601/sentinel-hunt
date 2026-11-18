import unittest
from unittest.mock import Mock

from sentinel_hunt.defender import isolate, resolve_machine
from sentinel_hunt.findings import resolve
from sentinel_hunt.query import Search


class HuntTests(unittest.TestCase):
    def test_query_bounds(self):
        for hours in (0, 169, True):
            with self.assertRaises(ValueError):
                Search("SigninLogs", hours, "")
        with self.assertRaises(ValueError):
            Search("Missing", 1, "")

    def test_target_is_a_literal(self):
        query = Search("SigninLogs", 4, 'a"b').kql()
        self.assertIn(r'UserPrincipalName =~ "a\"b"', query)

    def test_evidence_bounds(self):
        finding = dict(title="t", assessment="a", confidence="low", technique="unknown", next_check="check")
        # JSON true decodes to a Python bool, which otherwise behaves like the integer 1.
        for ids in ([0], [2], [True], []):
            with self.assertRaises(ValueError):
                resolve({"findings": [dict(finding, evidence=ids)]}, [{}])

    def test_ambiguous_device(self):
        session = Mock()
        session.get.return_value.json.return_value = {"value": [{"id": "a"}, {"id": "b"}]}
        with self.assertRaises(ValueError):
            resolve_machine(session, "lab")

    def test_failed_isolation_is_not_success(self):
        session = Mock()
        session.post.return_value.status_code = 403
        with self.assertRaises(ValueError):
            isolate(session, "a")
