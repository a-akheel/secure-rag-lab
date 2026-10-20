# Secure RAG: an indirect prompt injection lab

A local teaching prototype demonstrating an unauthorized document read and its fix.
All records are fictional. Requires Python 3.9+; no extra dependencies.
The simulator needs no API key or network. The optional live model mode does.

**Two modes of learning:** `rag_demo.py` is the deterministic simulator described
below. `ai_demo.py` integrates real hosted models through Groq or NVIDIA; see
[the AI setup guide](AI_GUIDE.md). All 27 offline tests pass. User-run live
experiments demonstrated both an unauthorized disclosure and a blocked read;
see [experiment results and limitations](EXPERIMENTS.md).
Neither version proves resistance to all injections.

## Run the demonstration

In a terminal, enter this project's directory and run:

```sh
python3 rag_demo.py
```

This shows the same question and malicious document in two modes:

1. **Vulnerable:** the simulated agent requests payroll, and a deliberately missing
   permission check allows fictional salaries to appear in Alice's answer.
2. **Secure:** the same request is denied by application code, while the hotel
   limit and reimbursement instructions still appear.

The audit log explains each decision. It is a developer view, not an employee-facing
API response; even names of restricted documents can be sensitive in a real service.

## Learn by trying these scenarios

```sh
# A normal question with no attack in the FAQ
python3 rag_demo.py --clean

# Alice directly requests a restricted document
python3 rag_demo.py --mode secure --user alice --question read:payroll

# Bob has payroll permission
python3 rag_demo.py --mode secure --user bob --question read:payroll

# Inspect the result as structured data
python3 rag_demo.py --mode secure --json

# Run the security regression tests
python3 -m unittest -v
```

Before each run, predict whether payroll should be readable. Then compare your
prediction with the audit log. `read:payroll` is an explicit lab command, not a
natural-language interpretation feature.

## How the pieces fit together

```text
Lab user selection (Alice or Bob)
          |
          v
Question -> DocumentService.search -> permission filter -> relevant passages
                                                               |
                                                               v
                                                   Simulated agent
                                                               |
                                              document requests READ:payroll
                                                               |
                                                               v
                                             DocumentService.read
                                                /            \
                                       Alice: deny        Bob: allow
```

`rag_demo.py` contains the trusted user-to-role mapping, document access policy,
retrieval service, simulated agent, and command-line interface. `documents/`
contains reference text. `test_security.py` checks both failures and legitimate access.

### Step 1: Retrieval

Retrieval means finding useful information for a question. This lab ranks documents
by overlapping words and returns up to three matches. It uses whole documents,
not chunks, embeddings, or a vector database. Those can improve search, but are
unnecessary for demonstrating this permission boundary.

In secure mode the service excludes unauthorized documents **before reading their
contents for search**. Restricted text therefore never enters the agent's input.

### Step 2: The injected instruction

Compare `documents/faq.txt` with `documents/faq_injected.txt`. Both contain a
legitimate travel fact. The injected version also claims Alice has administrator
rights and tells the agent to read payroll.

The simulator interprets `[[READ:payroll]]` as the tool request a compromised agent
might make. This marker is a simulation mechanism, not an injection detection
algorithm. Real malicious instructions need not contain any such marker.

### Step 3: The trust boundary

The application owns the role mapping and access policy. Retrieved text does not.
A statement in a document that Alice is an administrator cannot change her role.

Each returned passage is labeled `untrusted_reference` and carries its source.
That label is explanatory metadata in this prototype; it does not itself enforce
security. The permission checks perform the enforcement.

### Step 4: Authorization on every read

Search filtering alone is insufficient: an agent might request a document ID
directly. `DocumentService.read` independently checks the selected user's role.
Unknown document IDs and paths are rejected. File paths come only from a fixed
application manifest.

The vulnerable mode intentionally bypasses role checks. The secure mode rejects
Alice's payroll request even though the simulated agent follows the attack.

### Step 5: Evidence and regression tests

The payroll file contains a **canary**, a unique fake string used to detect disclosure:
`SYNTHETIC_PAYROLL_CANARY_4821`. Tests establish that it appears in the vulnerable
attack output and does not appear in Alice's secure output. They also verify that
denied reads never fetch content, search filters before fetching, forged role claims
have no authority, unknown users and paths fail, and Bob retains legitimate access.

## Vocabulary

| Term | Meaning in this project |
|---|---|
| RAG | Retrieve reference information, then use it to produce an answer |
| Indirect prompt injection | Malicious instructions encountered inside retrieved content |
| Authentication | Establishing who a user is; not implemented in this local lab |
| Authorization | Deciding which documents that user may read |
| Role-based access control | Granting access through roles such as employee or payroll administrator |
| Trust boundary | Separation between reference text and trusted access decisions |
| Tool | An application function the agent can request, such as reading a document |
| Least privilege | Giving a user or component only the access its job requires |
| Audit log | A record of requested actions and permission decisions |
| Fail closed | Reject access when identity or policy is unknown |
| Regression test | A repeatable check that catches a broken protection after code changes |
| Exfiltration | Disclosure of data to an unauthorized person or destination |

## Threat model and limits

The attacker can alter the FAQ body. They cannot change application code, user
identity, the trusted document manifest, or the role policy. Their goal is to expose
payroll to Alice through the assistant. Alice controls a legitimate question.

This is a local educational program. `--user bob` selects a scenario; it is not
authentication. Anyone with filesystem access can read the fictional documents.
The protection being demonstrated is the document-service boundary used by the
simulated agent, not operating-system isolation.

The simulator extracts lines labeled `FACT:` rather than generating natural language.
It does not assess truthfulness. An attacker could alter an allowed fact and affect
the answer. Access control does not solve answer poisoning, all permitted-data
misuse, or every prompt-injection risk. There are no external tools, outbound
requests in the simulator, shared caches, real login sessions, or persistent audit
storage. The optional AI version sends reference data to the selected provider.

## A short presentation script

1. Explain Alice's hotel question and the payroll restriction.
2. Show the malicious FAQ and its forged claim of authority.
3. Run the default comparison. Point out the exposed canary in vulnerable mode.
4. Show the denied read in secure mode and the useful travel answer that remains.
5. Run Bob's direct request to show that authorized access still works.
6. Run the tests. State clearly that this is a simulation of agent behavior.

## Next learning milestone

Run the new real-model integration using [AI_GUIDE.md](AI_GUIDE.md), preserving
the document-service checks. Later, bind user identity to a verified server-side
session instead of a CLI flag.
Keep reference text separate from trusted model instructions. Test several attack
wordings and repeated runs, measuring model tool requests separately from actual
unauthorized reads. A model refusing an attack and an application blocking an
attempted action are distinct outcomes.
