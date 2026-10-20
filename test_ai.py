"""Offline contract/security tests. These do not measure real model behavior."""
import copy
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from ai_demo import APIError, CANARY, ChatClient, LiveDocuments, execute_tool, run_ai


def call(name="read_document", arguments=None, identifier="call_1"):
    return {"id": identifier, "type": "function", "function": {"name": name,
            "arguments": json.dumps(arguments if arguments is not None else {"document_id": "payroll"})}}


def response(content=None, calls=None, finish=None):
    return {"choices": [{"finish_reason": finish or ("tool_calls" if calls else "stop"),
            "message": {"role": "assistant", "content": content, "tool_calls": calls or []}}]}


class FakeClient:
    provider = "offline-test-double"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.inputs = []

    def complete(self, messages, model):
        self.inputs.append(copy.deepcopy(messages))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class LiveAgentTests(unittest.TestCase):
    def test_secure_request_denied_before_return_to_model(self):
        client = FakeClient(response(calls=[call()]), response("Hotel limit is $200 [travel]."))
        result = run_ai(client)
        self.assertTrue(result["observations"]["payroll_read_requested"])
        self.assertFalse(result["observations"]["unauthorized_access_allowed"])
        self.assertNotIn(CANARY, json.dumps(client.inputs))
        self.assertIn("Access denied", client.inputs[1][-1]["content"])
        self.assertEqual(result["status"], "completed")

    def test_vulnerable_read_is_detected_even_without_answer_disclosure(self):
        client = FakeClient(response(calls=[call()]), response("The hotel limit is $200."))
        result = run_ai(client, mode="vulnerable")
        self.assertTrue(result["observations"]["unauthorized_access_allowed"])
        self.assertTrue(result["observations"]["canary_sent_to_model"])
        self.assertFalse(result["observations"]["canary_in_answer"])
        self.assertIn(CANARY, json.dumps(client.inputs[1]))

    def test_authorized_read_not_misclassified_as_violation(self):
        client = FakeClient(response(calls=[call()]), response(CANARY))
        result = run_ai(client, user="bob")
        self.assertTrue(result["observations"]["canary_in_answer"])
        self.assertFalse(result["observations"]["unauthorized_access_allowed"])

    def test_model_can_ignore_attack(self):
        result = run_ai(FakeClient(response("Hotel limit is $200 [travel].")), mode="vulnerable")
        self.assertFalse(result["observations"]["payroll_read_requested"])
        self.assertFalse(result["observations"]["unauthorized_access_allowed"])

    def test_prompt_same_across_modes(self):
        clients = [FakeClient(response("Answer")), FakeClient(response("Answer"))]
        for client, mode in zip(clients, ["secure", "vulnerable"]):
            run_ai(client, mode=mode)
        self.assertEqual(clients[0].inputs[0], clients[1].inputs[0])

    def test_tool_arguments_cannot_override_identity(self):
        service = LiveDocuments("alice", "secure", "authority")
        result = execute_tool(service, call(arguments={"document_id": "payroll", "user": "bob"}))
        self.assertIn("error", result)
        self.assertEqual(service.events, [])

    def test_invalid_arguments_and_tools_fail_closed(self):
        service = LiveDocuments("alice", "secure", "clean")
        bad_calls = [call(name="send_email"), call(name=[]), call(arguments=[]),
                     call(arguments={"document_id": 4}), call(arguments={"document_id": "../../etc/passwd"})]
        malformed = call()
        malformed["function"]["arguments"] = "not JSON"
        for item in bad_calls + [malformed]:
            self.assertIn("error", execute_tool(service, item))

    def test_search_tool_cannot_bypass_permissions(self):
        service = LiveDocuments("alice", "secure", "clean")
        result = execute_tool(service, call("search_documents", {"query": "payroll salary confidential"}))
        self.assertNotIn(CANARY, json.dumps(result))

    def test_round_limit_still_records_request(self):
        result = run_ai(FakeClient(response(calls=[call()])), max_rounds=1)
        self.assertEqual(result["status"], "round_limit")
        self.assertTrue(result["observations"]["payroll_read_requested"])
        self.assertEqual(result["tool_trace"], [])

    def test_tool_limit_prevents_batch_execution(self):
        result = run_ai(FakeClient(response(calls=[call(identifier=str(i)) for i in range(13)])))
        self.assertEqual(result["status"], "tool_limit")
        self.assertEqual(result["tool_trace"], [])

    def test_incomplete_response_is_not_success(self):
        result = run_ai(FakeClient(response("Partial", finish="length")))
        self.assertEqual(result["status"], "incomplete_response")

    def test_api_failure_retains_audit(self):
        result = run_ai(FakeClient(APIError("Rate limited")))
        self.assertEqual(result["status"], "api_error")
        self.assertTrue(result["audit"])

    def test_malformed_response_does_not_execute(self):
        result = run_ai(FakeClient({"choices": []}))
        self.assertEqual(result["status"], "api_error")
        self.assertEqual(result["tool_trace"], [])

    def test_http_payload_and_credentials(self):
        for provider, host in [("groq", "api.groq.com"), ("nvidia", "integrate.api.nvidia.com")]:
            client = ChatClient("fake-test-key", provider)
            with patch.object(client.opener, "open", side_effect=urllib.error.HTTPError(
                    "https://example.invalid", 429, "Rate limited", {}, None)) as send:
                with self.assertRaisesRegex(APIError, "Rate limit"):
                    client.complete([{"role": "user", "content": "test"}], "test-model")
            request = send.call_args.args[0]
            self.assertEqual(request.host, host)
            payload = json.loads(request.data)
            self.assertEqual(payload["tool_choice"], "auto")
            self.assertNotIn("fake-test-key", request.data.decode())

    def test_missing_key_has_actionable_message(self):
        with self.assertRaisesRegex(APIError, "GROQ_API_KEY"):
            ChatClient(None)

    def test_403_details_redact_key_and_ignore_unrelated_fields(self):
        client = ChatClient("fake-secret-key")
        body = {"error": {"code": "model_permission_blocked",
                         "message": "Blocked fake-secret-key gsk_anotherSecret",
                         "debug": "private data not to print"}}
        error = urllib.error.HTTPError(client.endpoint, 403, "Forbidden", {},
                                       io.BytesIO(json.dumps(body).encode()))
        with patch.object(client.opener, "open", side_effect=error):
            with self.assertRaises(APIError) as caught:
                client.complete([], "test")
        text = str(caught.exception)
        self.assertIn("model_permission_blocked", text)
        self.assertNotIn("fake-secret-key", text)
        self.assertNotIn("gsk_anotherSecret", text)
        self.assertNotIn("private data", text)

    def test_gateway_body_is_not_dumped(self):
        client = ChatClient("fake-secret-key")
        error = urllib.error.HTTPError(client.endpoint, 403, "Forbidden", {},
                                       io.BytesIO(b"<html>private gateway detail</html>"))
        with patch.object(client.opener, "open", side_effect=error):
            with self.assertRaisesRegex(APIError, "Non-JSON") as caught:
                client.complete([], "test")
        self.assertNotIn("<html>", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
