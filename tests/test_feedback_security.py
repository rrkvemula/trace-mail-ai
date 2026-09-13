import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request
from starlette.responses import PlainTextResponse

import app as tracemail_app
from app import FeedbackStore, bind_user_allowlist


class FeedbackSecurityTests(unittest.TestCase):
    """Regression tests for authenticated, user-scoped, durable analyst feedback."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store_path = str(Path(self.tempdir.name) / "user_feedback.jsonl")
        self.original_store = tracemail_app.FEEDBACK_STORE
        tracemail_app.FEEDBACK_STORE = FeedbackStore(self.store_path)

    def tearDown(self):
        tracemail_app.FEEDBACK_STORE = self.original_store
        self.tempdir.cleanup()

    def test_feedback_requires_bearer_authentication(self):
        from fastapi import HTTPException

        with patch.dict(os.environ, {"TRACEMAIL_LOCAL_ANALYST_KEY": ""}):
            with self.assertRaises(HTTPException) as ctx:
                self.submit_feedback(
                    feedback_type="ALLOWLIST_SENDER",
                    sender_email="billing@trusted-vendor.com",
                    sender_domain="trusted-vendor.com",
                )
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertFalse(Path(self.store_path).exists())

    def test_feedback_is_persisted_and_scoped_to_authenticated_analyst(self):
        claims = {"uid": "analyst-one", "email": "analyst.one@corp.com"}
        with patch.object(tracemail_app, "verify_firebase_bearer_token", return_value=claims):
            response = self.submit_feedback(
                analysis_id="ANL-TEST",
                feedback_type="ALLOWLIST_SENDER",
                sender_email="billing@trusted-vendor.com",
                sender_domain="trusted-vendor.com",
                notes="trusted vendor",
            )
        self.assertEqual(response.status, "RECORDED")
        body = response.model_dump()
        self.assertEqual(body["status"], "RECORDED")
        self.assertEqual(body["scoped_to"], "analyst-one")

        entries = [json.loads(line) for line in Path(self.store_path).read_text().splitlines()]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["owner_uid"], "analyst-one")
        self.assertEqual(entries[0]["sender_email"], "billing@trusted-vendor.com")

        self.assertEqual(
            tracemail_app.FEEDBACK_STORE.allowlist_for("analyst-one"),
            {"billing@trusted-vendor.com", "trusted-vendor.com"},
        )
        self.assertEqual(tracemail_app.FEEDBACK_STORE.allowlist_for("analyst-two"), set())

    def test_shared_consumer_domains_are_not_globally_allowlisted(self):
        claims = {"uid": "analyst-one"}
        with patch.object(tracemail_app, "verify_firebase_bearer_token", return_value=claims):
            response = self.submit_feedback(
                feedback_type="ALLOWLIST_SENDER",
                sender_email="user@gmail.com",
                sender_domain="gmail.com",
            )
        self.assertEqual(response.status, "RECORDED")
        self.assertEqual(
            tracemail_app.FEEDBACK_STORE.allowlist_for("analyst-one"),
            {"user@gmail.com"},
        )

    def test_invalid_feedback_target_is_rejected_without_persistence(self):
        from fastapi import HTTPException

        claims = {"uid": "analyst-one"}
        with patch.object(tracemail_app, "verify_firebase_bearer_token", return_value=claims):
            with self.assertRaises(HTTPException) as ctx:
                self.submit_feedback(
                    feedback_type="ALLOWLIST_SENDER",
                    sender_email="not-an-email",
                )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertFalse(Path(self.store_path).exists())

    def submit_feedback(self, **payload):
        import asyncio
        from app import FeedbackRequest
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/feedback",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)
        return asyncio.run(
            tracemail_app.record_user_feedback(request, FeedbackRequest(**payload))
        )

    def test_scan_binds_only_the_authenticated_analyst_allowlist(self):
        store = FeedbackStore(self.store_path)
        store.append(
            {
                "timestamp": "2026-09-13T00:00:00+00:00",
                "owner_uid": "analyst-one",
                "feedback_type": "ALLOWLIST_SENDER",
                "sender_email": "billing@trusted-vendor.com",
                "sender_domain": "trusted-vendor.com",
            }
        )
        tracemail_app.FEEDBACK_STORE = store

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/scan",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)

        async def next_request(req):
            return PlainTextResponse("OK")

        import asyncio
        with patch.object(tracemail_app, "verify_firebase_bearer_token", return_value={"uid": "analyst-one"}):
            asyncio.run(bind_user_allowlist(request, next_request))
        self.assertEqual(request.state.analyst_uid, "analyst-one")
        self.assertEqual(
            request.state.user_allowlist,
            {"billing@trusted-vendor.com", "trusted-vendor.com"},
        )

    def test_unauthenticated_scan_gets_empty_allowlist(self):
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/scan",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)

        async def next_request(req):
            return PlainTextResponse("OK")

        import asyncio
        asyncio.run(bind_user_allowlist(request, next_request))
        self.assertIsNone(request.state.analyst_uid)
        self.assertEqual(request.state.user_allowlist, set())


if __name__ == "__main__":
    unittest.main()
