"""Run with:  python -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402
from features import URL_FEATURE_NAMES, extract_url_features, find_urls, message_signals  # noqa: E402


class ThreatLensTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = app.test_client()

    def msg(self, text):
        return self.c.post("/api/analyze/message", json={"text": text})

    def url(self, u):
        return self.c.post("/api/analyze/url", json={"url": u})

    # --- features
    def test_feature_vector_length(self):
        self.assertEqual(len(extract_url_features("http://a.com")), len(URL_FEATURE_NAMES))

    def test_highlights_in_bounds(self):
        text = "Click here now: http://evil.xyz/login URGENT ₹5000 prize"
        _, hl = message_signals(text)
        self.assertTrue(hl)
        self.assertTrue(all(0 <= s < e <= len(text) for s, e, _ in hl))

    def test_email_address_is_not_a_link(self):
        self.assertEqual(find_urls("write to help@bank.com for details"), [])

    # --- messages
    def test_scam_message_flagged(self):
        r = self.msg("URGENT: your SBI account will be blocked. Update KYC at http://sbi-kyc.xyz/login and share OTP").get_json()
        self.assertEqual(r["verdict"]["level"], "danger")
        self.assertTrue(r["signals"] and r["highlights"])

    def test_prize_and_fee_scam_flagged(self):
        r = self.msg("You won a lottery prize of Rs 50000! Pay a small processing fee to claim.").get_json()
        self.assertEqual(r["verdict"]["level"], "danger")

    def test_ordinary_message_safe(self):
        r = self.msg("Are we still meeting at 5 for tea? I'll bring the notes.").get_json()
        self.assertEqual(r["verdict"]["level"], "safe")

    def test_genuine_otp_notice_not_flagged(self):
        r = self.msg("Your OTP for HDFC Bank login is 483920. Do not share it with anyone.").get_json()
        self.assertEqual(r["verdict"]["level"], "safe")

    # --- urls
    def test_phishing_url_flagged(self):
        self.assertEqual(self.url("http://paypal-secure-login.top/verify").get_json()["verdict"]["level"], "danger")

    def test_ip_url_has_reason(self):
        r = self.url("http://192.168.4.7/hdfc/login.html").get_json()
        self.assertEqual(r["verdict"]["level"], "danger")
        self.assertTrue(any("IP" in s["title"] for s in r["signals"]))

    def test_genuine_sites_not_flagged(self):
        for u in ["https://accounts.google.com/signin", "https://www.sbi.co.in/",
                  "https://netbanking.hdfcbank.com/login", "https://github.com/pallets/flask"]:
            with self.subTest(u=u):
                self.assertEqual(self.url(u).get_json()["verdict"]["level"], "safe")

    def test_shortener_is_suspicious_not_condemned(self):
        self.assertEqual(self.url("bit.ly/3xKq9").get_json()["verdict"]["level"], "warning")

    # --- validation / serving
    def test_bad_input_rejected(self):
        self.assertEqual(self.msg("   ").status_code, 400)
        self.assertEqual(self.msg("a" * 5001).status_code, 400)
        self.assertEqual(self.url("two words").status_code, 400)
        self.assertEqual(self.c.post("/api/analyze/url", data="not json").status_code, 400)

    def test_three_pages_served(self):
        home, check, result = (self.c.get(p) for p in ("/", "/check", "/result"))
        self.assertEqual((home.status_code, check.status_code, result.status_code), (200, 200, 200))
        self.assertIn(b"Check a message", home.data)
        self.assertIn(b"What do you want to check?", check.data)
        self.assertIn(b'id="verdict-label"', result.data)

    def test_nav_marks_current_page(self):
        self.assertIn(b'href="/check"  aria-current="page"', self.c.get("/check").data)

    def test_health(self):
        self.assertEqual(self.c.get("/api/health").get_json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
