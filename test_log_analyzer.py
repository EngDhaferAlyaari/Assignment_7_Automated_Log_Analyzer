"""Small tests for Assignment 7. Run with python -m unittest -v."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import log_analyzer as app


class DetectionTests(unittest.TestCase):
    def test_union_select(self):
        self.assertEqual(app.detect_attacks('GET /?q=UNION SELECT password'), ['SQL Injection'])

    def test_case_insensitive(self):
        self.assertIn('SQL Injection', app.detect_attacks('union select x'))

    def test_union_all_select(self):
        self.assertIn('SQL Injection', app.detect_attacks('UNION ALL SELECT username'))

    def test_encoded_sql(self):
        self.assertIn('SQL Injection', app.detect_attacks('UNION%20SELECT'))

    def test_double_encoded_sql(self):
        self.assertIn('SQL Injection', app.detect_attacks('UNION%2520SELECT'))

    def test_or_one_equals_one(self):
        self.assertIn('SQL Injection', app.detect_attacks('id=1 OR 1=1'))

    def test_and_quoted_one_equals_one(self):
        self.assertIn('SQL Injection', app.detect_attacks("id=1 AND '1'='1'"))

    def test_normal_select_word(self):
        self.assertEqual(app.detect_attacks('SELECT is used in SQL lessons'), [])

    def test_normal_union_word(self):
        self.assertEqual(app.detect_attacks('union members arrived'), [])

    def test_path_traversal(self):
        self.assertIn('Path Traversal', app.detect_attacks('../etc/passwd'))

    def test_deep_traversal(self):
        self.assertIn('Path Traversal', app.detect_attacks('../../../private/config'))

    def test_windows_traversal(self):
        self.assertIn('Path Traversal', app.detect_attacks('..\\windows\\win.ini'))

    def test_encoded_traversal(self):
        self.assertIn('Path Traversal', app.detect_attacks('..%2Fetc%2Fpasswd'))

    def test_double_encoded_traversal(self):
        self.assertIn('Path Traversal', app.detect_attacks('..%252Fetc%252Fpasswd'))

    def test_benign_etc_passwd_reference(self):
        self.assertEqual(app.detect_attacks('Documentation mentions /etc/passwd'), [])

    def test_benign_log(self):
        self.assertEqual(app.detect_attacks('192.168.1.1 GET /home 200'), [])

    def test_multiple_types_one_line(self):
        self.assertEqual(app.detect_attacks('UNION SELECT x ../etc/passwd'), ['SQL Injection', 'Path Traversal'])

    def test_ipv4(self):
        self.assertEqual(app.extract_ip('client 10.20.30.40 attack'), '10.20.30.40')

    def test_invalid_ip_skipped(self):
        self.assertEqual(app.extract_ip('999.2.3.4 then 192.0.2.5'), '192.0.2.5')

    def test_unknown_ip(self):
        self.assertEqual(app.extract_ip('UNION SELECT x'), 'Unknown')


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / 'log.txt'

    def analyze(self, content):
        self.log.write_text(content, encoding='utf-8')
        output = io.StringIO()
        matches = app.analyze_log(self.log, output)
        return matches, output.getvalue()

    def test_line_numbers(self):
        count, report = self.analyze('ok\nUNION SELECT x\nok\n../etc/passwd\n')
        self.assertEqual(count, 2)
        self.assertIn('Line 2', report)
        self.assertIn('Line 4', report)

    def test_summary(self):
        _, report = self.analyze('ok\nUNION SELECT x\n../../etc/passwd\n')
        for expected in ['Total lines: 3', 'Suspicious lines: 2', 'Normal lines: 1', 'SQL Injection: 1', 'Path Traversal: 1']:
            self.assertIn(expected, report)

    def test_same_line_counted_once(self):
        count, report = self.analyze('UNION SELECT x ../../etc/passwd\n')
        self.assertEqual(count, 1)
        self.assertIn('Suspicious lines: 1', report)
        self.assertIn('SQL Injection: 1', report)
        self.assertIn('Path Traversal: 1', report)

    def test_empty_log(self):
        count, report = self.analyze('')
        self.assertEqual(count, 0)
        self.assertIn('Total lines: 0', report)

    def test_only_normal_log(self):
        count, report = self.analyze('GET / 200\nGET /docs 200\n')
        self.assertEqual(count, 0)
        self.assertNotIn('[ALERT]', report)

    def test_unicode_log(self):
        count, report = self.analyze('مرحبا\n10.0.0.1 UNION SELECT password\n')
        self.assertEqual(count, 1)
        self.assertIn('IP: 10.0.0.1', report)

    def test_invalid_utf8_replaced(self):
        self.log.write_bytes(b'\xff Normal\n192.0.2.4 UNION SELECT x\n')
        output = io.StringIO()
        self.assertEqual(app.analyze_log(self.log, output), 1)

    def test_crlf(self):
        self.log.write_bytes(b'normal\r\nUNION SELECT something\r\n')
        output = io.StringIO()
        self.assertEqual(app.analyze_log(self.log, output), 1)
        self.assertIn('Line 2', output.getvalue())

    def test_large_file(self):
        with self.log.open('w', encoding='utf-8') as handle:
            for i in range(20000):
                handle.write('192.168.1.3 GET / OK\n')
            handle.write('192.168.1.4 UNION SELECT email\n')
        output = io.StringIO()
        self.assertEqual(app.analyze_log(self.log, output), 1)
        self.assertIn('Line 20001', output.getvalue())
        self.assertIn('Total lines: 20001', output.getvalue())

    def test_missing_log_returns_error(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            code = app.main([str(self.log)])
        self.assertEqual(code, 1)
        self.assertIn('Error:', errors.getvalue())

    def test_report_file_created(self):
        self.log.write_text('UNION SELECT username\n', encoding='utf-8')
        report_path = Path(self.tmp.name) / 'report.txt'
        with redirect_stdout(io.StringIO()):
            code = app.main([str(self.log), '--report', str(report_path)])
        self.assertEqual(code, 0)
        self.assertIn('SQL Injection', report_path.read_text(encoding='utf-8'))

    def test_missing_report_folder_returns_error(self):
        self.log.write_text('ok\n', encoding='utf-8')
        errors = io.StringIO()
        with redirect_stderr(errors):
            code = app.main([str(self.log), '--report', str(Path(self.tmp.name) / 'missing' / 'report.txt')])
        self.assertEqual(code, 1)

    def test_sample_fixture(self):
        sample = Path(__file__).with_name('sample_security.log')
        output = io.StringIO()
        matches = app.analyze_log(sample, output)
        self.assertEqual(matches, 4)
        self.assertIn('SQL Injection: 2', output.getvalue())
        self.assertIn('Path Traversal: 2', output.getvalue())


if __name__ == '__main__':
    unittest.main()
