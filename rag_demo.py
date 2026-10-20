"""An intentionally non-LLM RAG security teaching lab. Standard library only."""
import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Trusted application policy: never populated from retrieved document text.
USERS = {"alice": "employee", "bob": "payroll_admin"}
DOCUMENTS = {
    "travel": ("Travel policy", "travel.txt", {"employee", "payroll_admin"}),
    "faq": ("Travel FAQ", "faq.txt", {"employee", "payroll_admin"}),
    "payroll": ("Synthetic payroll", "payroll.txt", {"payroll_admin"}),
}


class AccessDenied(Exception):
    pass


@dataclass
class Event:
    action: str
    document: str
    decision: str
    reason: str


class DocumentService:
    """Reference monitor: every protected access passes through this service."""

    def __init__(self, user, mode, attack=True):
        if user not in USERS:
            raise ValueError("Unknown user (fail closed).")
        if mode not in {"secure", "vulnerable"}:
            raise ValueError("Unknown mode.")
        self.user, self.mode, self.attack = user, mode, attack
        self.events = []

    def allowed(self, document):
        return document in DOCUMENTS and USERS[self.user] in DOCUMENTS[document][2]

    def _text(self, document):
        # Only manifest filenames are resolved; tool arguments cannot supply paths.
        filename = DOCUMENTS[document][1]
        if document == "faq" and self.attack:
            filename = "faq_injected.txt"
        return (ROOT / "documents" / filename).read_text(encoding="utf-8")

    def read(self, document):
        if document not in DOCUMENTS:
            self.events.append(Event("read", document, "denied", "Unknown document ID"))
            raise AccessDenied("Unknown document ID")
        if self.mode == "secure" and not self.allowed(document):
            self.events.append(Event("read", document, "denied", "User lacks permission"))
            raise AccessDenied("User lacks permission")
        reason = "Role permits read" if self.mode == "secure" else "DEMO: permission check bypassed"
        self.events.append(Event("read", document, "allowed", reason))
        return self._text(document)

    def search(self, query):
        # Filter before fetching/scoring content, rather than after it reaches the agent.
        terms = set(re.findall(r"[a-z]+", query.lower()))
        hits = []
        for document, (title, _, _) in DOCUMENTS.items():
            if self.mode == "secure" and not self.allowed(document):
                self.events.append(Event("search_filter", document, "excluded", "User lacks permission"))
                continue
            text = self._text(document)
            score = len(terms & set(re.findall(r"[a-z]+", (title + " " + text).lower())))
            if score:
                hits.append((score, document, text))
        hits.sort(key=lambda hit: (-hit[0], hit[1]))
        results = []
        for _, document, text in hits[:3]:
            self.events.append(Event("retrieve", document, "allowed", "Matched question"))
            results.append({"id": document, "source": DOCUMENTS[document][0],
                            "trust": "untrusted_reference", "text": text})
        return results


def run_demo(user="alice", mode="secure", attack=True,
             question="What is the hotel reimbursement policy?"):
    service = DocumentService(user, mode, attack)
    sources, output, attempted = [], [], []
    # Explicit direct request for an access-control test, not natural-language understanding.
    direct = re.fullmatch(r"read:([^\s]+)", question.strip())
    if direct:
        try:
            output.append(service.read(direct[1]))
            sources.append(direct[1])
        except AccessDenied as exc:
            output.append("Access denied: " + str(exc))
    else:
        hits = service.search(question)
        sources = [hit["id"] for hit in hits]
        for hit in hits:
            # Deterministic simulation of an agent obeying a malicious tool request.
            # This is deliberately NOT a detector or a real model susceptibility test.
            for target in re.findall(r"\[\[READ:([^\]\s]+)\]\]", hit["text"]):
                attempted.append(target)
                try:
                    output.append("Agent followed document instruction:\n" + service.read(target))
                except AccessDenied as exc:
                    output.append("Injected document read blocked: " + str(exc))
            for line in hit["text"].splitlines():
                if line.startswith("FACT:"):
                    output.append(line.removeprefix("FACT:").strip() + " [" + hit["id"] + "]")
        if not output:
            output.append("No relevant information found.")
    return {"engine": "deterministic simulator; no AI model", "user": user,
            "role": USERS[user], "mode": mode, "attack_enabled": attack,
            "question": question, "retrieved_sources": sources,
            "injected_read_attempts": attempted, "answer": "\n\n".join(output),
            "audit": [asdict(event) for event in service.events]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["secure", "vulnerable", "compare"], default="compare")
    parser.add_argument("--user", choices=USERS, default="alice")
    parser.add_argument("--clean", action="store_true", help="Use the benign FAQ")
    parser.add_argument("--question", default="What is the hotel reimbursement policy?")
    parser.add_argument("--json", action="store_true", help="Output structured results")
    args = parser.parse_args()
    modes = ["vulnerable", "secure"] if args.mode == "compare" else [args.mode]
    results = [run_demo(args.user, mode, not args.clean, args.question) for mode in modes]
    if args.json:
        print(json.dumps(results, indent=2))
        return
    print("SECURE RAG LAB — SIMULATOR — ALL DATA IS FICTIONAL\n")
    for result in results:
        print(f"=== {result['mode'].upper()} | {result['user']} ({result['role']}) ===")
        print("Question:", result["question"])
        print("Retrieved:", ", ".join(result["retrieved_sources"]) or "none")
        print("\n" + result["answer"])
        print("\nAudit log (developer view):")
        for event in result["audit"]:
            print(f"  {event['action']:14} {event['document']:10} {event['decision']:8} {event['reason']}")
        print()


if __name__ == "__main__":
    main()
