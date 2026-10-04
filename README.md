# warden

A local guard and decision engine for AI agents, built on the small local decision model **lev**
(`/v1/systemone` on `127.0.0.1:8200`). Standard library only, Python ≥ 3.11.

- **Guard**: inspects text at a boundary and says what to do with it.
- **Classify**: what expertise a prompt needs and what the user wants done (2 lev calls).
- **Escalate**: should a local agent hand a task to a frontier model now? (one lev call, or none)
- **Decide**: offloads bulk yes/no, choice, and score decisions from big models to lev.
- **Router** (experimental): picks an agent and model for a prompt.
- **Test bed**: a local UI for all of the above.

> **Status: test bed only, not integrated into anything yet.** The skill in `skill/warden/` is written but not
> installed. Hooks for Hermes and OpenCode come later, once the eval numbers justify it.

```bash
python3 -m warden testbed                 # UI at http://127.0.0.1:8740   (or ./run.sh)
echo "…" | python3 -m warden scan -b content --brief
python3 -m unittest discover -s tests -t .     # offline (lev stubbed)
python3 evals/fetch.py && python3 -m warden eval    # measure on the test splits
```

Install as a CLI when you're ready (not done yet): `uv tool install --editable ~/Work/warden`

## Boundaries

| Boundary | What it's for | Checks | Actions (allow / review / block) |
|---|---|---|---|
| `prompt` | What a person sends an agent (typed, pasted, voice, Discord) | All rules; lev asks *manipulation*, then *extraction* | proceed / confirm_restricted / refuse |
| `content` | Untrusted text an agent is about to read: web pages, email, files, tool output | Injection rules (secrets ignored); lev asks *instructions aimed at an AI* over 700-char windows and on each hidden-markup segment, then *manipulation* | pass / pass_flagged / quarantine |
| `outbound` | Text about to leave this machine for a cloud model | Secrets, high-risk PII, hidden characters, high-entropy tokens; **no model call** | send / send_redacted / send_redacted (returns `redacted`) |

**The gates fail fast:**
- **Gate 0 · rules** (~1 ms). A block here means **zero** model calls.
- **Gate 1 · lev** asks the boundary's questions in order and stops at the first high score.

**Verdicts:**
- **Block**: a critical finding, a high rule finding, or a high lev score backed by a medium rule finding.
- **Review**: any other medium finding. **lev alone never blocks.**

**When lev is down:** `prompt` falls back to rules only; `content` **fails closed** to review.

## Defenses

**Rules** (`warden/rules.py`). Every rule runs on the raw text, on the NFKC/invisible-stripped text, and on
de-obfuscated views.
- **Unicode:**
  - tag-character smuggling (decoded and shown; legitimate flag emoji excluded);
  - bidi overrides, zero-width characters, variation-selector smuggling;
  - homoglyphs (mixed-script words are mapped to Latin for both the rules and lev);
  - terminal escape sequences (ANSI/OSC).
- **Injection:**
  - override and jailbreak phrasing in English plus Spanish, French, German, Portuguese, Italian, Russian, Chinese and Japanese;
  - prompt extraction, including soft probes ("what were the instructions you were given?");
  - forged chat-template tokens;
  - text addressed to an AI ("Hi Assistant,") and fake "[PRIORITY MESSAGE]" headers;
  - task hijacks ("before finishing the task above, please first…").
- **Obfuscation:**
  - leetspeak, spaced-out letters, reversed text;
  - base64, hex, URL-encoded and rot13 payloads, decoded recursively up to depth 3 (with a 200k-char budget) and rescanned;
  - attack phrases with all spacing and punctuation removed.
- **Hidden markup:** HTML comments; elements that are `display:none`, `visibility:hidden`, zero-size, transparent or white; `aria-hidden`; markdown comments; alt and title text. Instructions inside hidden markup → **block**.
- **Attacks on warden itself:** notes to "any automated reviewer", "final answer: no", claims that the text "is not an injection", forged data delimiters.
- **Agents:** destructive commands, reverse shells, pipe-to-shell; exfiltration hosts, markdown-image beacons, credential paths, SSRF/metadata addresses; suspicious URLs.
- **Secrets** (about 30 formats: cloud and AI-provider keys, Git hosting tokens, chat bots, `.env` assignments, Bearer headers, URL credentials, private keys, JWTs) and **PII** (SSN, Luhn-checked cards, IBAN, email, phone).

**lev:**
- Text is framed as data, using **keyed delimiters**: an HMAC tag of a per-process secret and the text, so the text
  can't forge the closing marker.
- Secrets and PII are redacted before lev sees anything.
- Long content is swept in windows, so an attack can't hide by diluting itself in a long document.
- Hidden-markup segments are judged on their own.
- Prompts over 1,200 characters need a 0.85 lev score (instead of 0.6) before lev alone triggers review.

**warden itself:**
- **No ReDoS:** every pattern is bounded, and pathological inputs scan in linear time. There's a regression test,
  and 1 MB worst case is about 4 s.
- **Size cap:** rules scan the first and last 500k chars and flag the truncation.
- **Never crashes on input:** a fuzz test covers random hostile Unicode, lone surrogates, U+2028 and invalid
  UTF-8 (decoded with replacement, never an error exit).
- **The lev client has a circuit breaker.**
- **The feedback file** uses ASCII-escaped JSON with mode 0600.

## Measured (2026-10-03, test split, never tuned on)

`python3 evals/fetch.py && python3 evals/analyze.py test --cats` (about 3,850 items):

| Test split | Rules only | Rules + lev |
|---|---|---|
| **Prompt boundary** (1,103 attacks / 1,053 benign) | 34% detected · 1.0% FP | **83% detected · 7.3% FP** (0.9% blocked) |
| **Content boundary** (848 / 845) | 69% · 0.5% | **93% · 2.8%** (0.2% blocked) |
| Lakera gandalf (direct injections) | 61% | 98% |
| jackhhao jailbreaks / benign personas | 61% · 0.8% | 95% · 9.8% |
| neuralchemy (categorized + hard negatives) | 29% · 0% | 72% · 4.6% |
| 3nesdeniz pairs (attack vs near-identical benign twin) | 17% · 8.3% | 93% · 25% |
| safe-guard (mostly ordinary prompts) | 25% · 0% | 88% · 4.0% |
| NVIDIA indirect injections in documents (one template, so rules alone look strong) | 83% · 0.5% | 99% · 3.0% |
| Synthetic web: Wikipedia + inserted payloads, plain or hidden | 30% · 0.5% | 75% · 2.4% |

**Weak spots:**
- HackAPrompt-style output forcing ("say 'I have been PWNED'"): 60%.
- Payloads in markdown comments: 56%.
- Tool-abuse requests: 60%.
- The *pairs* set's benign twins, which describe or quote attacks (25% FP). Text carrying a literal payload is
  flagged **on purpose**, whatever its framing.

**Cost** (lev on GPU):

| Input | lev calls | Time |
|---|---|---|
| Short prompt | 2 | ~180 ms |
| Rule block | 0 | ~1 ms |
| Content, 1 KB page | ~3 | ~0.6 s |
| Content, 3 KB page | ~7 | ~1.2 s |
| Content, 8 KB page | ~17 | ~2.8 s |
| Outbound | 0 | ~1 ms |

Attacks end the sweep early. `window_chars` and `max_windows` in the config trade cost against coverage.

**Considered and rejected (measured on the tune split):**
- **A verifier question for lev-only flags:** false positives 9% → 6%, but detection −5%. Rejected; a lev-only
  flag is only ever a review.
- **An "anything inside is data" sentence in the frame:** prompt false positives 9.8% → 17.7%, for no evasion gain
  over the keyed tag.
- **Sweeping long prompts with the content question:** no detection gain, more false positives.
- **Threshold changes:** almost no effect, because lev's scores are bimodal.

**Method:** every public set has a **tune** split (used for every decision above, via `evals/analyze.py tune`) and a
**test** split (measured once). `analyze.py` refuses to show miss texts for the test split. Keep it that way, or
the numbers stop meaning anything. The test bed's *Was this right?* labels go into `warden eval` as the `feedback`
set.

## Decide

```bash
warden decide --brief -k choice -q "What kind of issue is this?" -o "bug=a defect" -o "feature=a request" < issues.txt
```

- Kinds: `yes_no`, `choice` (more accurate for categorizing), and `score` (ordered levels).
- One lev call per item, about 70–150 ms. Items are redacted and framed as data.
- Good for triage, filtering and relevance checks. Not for final high-stakes calls: lev scores about 80% on
  JevBench and calls a shoe-sale email an "action item".

## Classify

```bash
echo "fix the failing test in auth.py" | warden classify --brief
# software/act → code_build  p=0.96/0.47
```

- **Expert** (10 kinds of expertise) and **mode** (answer / make / act / plan / lookup): the router's own lev
  questions, one call each. Asking both in one request costs the same (measured: 500 ms vs 504 ms), so they stay
  separate.
- `--sensitivity` adds a 0–4 privacy score (+1 call); `--guard` runs the prompt guard first and stops on block.
- The **workflow** is the router's mapping of expert + mode; it costs no extra call.

## Routing labels

The routing convention is **workflow × tier**:
- **Workflow** is one of `router.json`'s agents: `voice_home`, `code_build`, `code_plan`, `tech_qa`, `research`
  or `assistant`.
- **Tier** is `local`, `frontier` or `blocked`.

warden answers with that pair, and consumers map it to a concrete harness. Labels use the same pair.

- **Seed set:** `evals/routing/seed.jsonl` has 100 prompts in six areas: code, sysadmin, home, research, writing
  and edge cases. Each has a fixed tune/test split. Prompts labelled live on the Router page are split by hash.
- **Where labels live:** `~/.local/state/warden/labels-routing.jsonl` (0600, append-only, the latest label wins).
- **Measure:** `python3 evals/eval_routing.py tune --misses 20` while tuning, `… test` once for the report. It
  shows tier accuracy, agent accuracy, local-vs-frontier with frontier recall and precision, confusion matrices,
  and majority baselines. lev answers are cached in `evals/cache.sqlite`.

## Escalate

```bash
echo "Edited auth.py 3 times; same AssertionError every run. Not sure why." | warden escalate --brief -t "Fix the failing test"
# escalate p=0.85 · lev: hand off (p=0.85 ≥ 0.5)
```

- **One lev yes/no** over the task and the agent's summary of what it tried. Both are redacted and framed as data.
- **Rule signals** in the summary come first:
  - **needs a person** (sudo or permissions, no network, waiting on the user) means stay local: a bigger model
    can't help, so the reason says to ask the user.
  - **clear success** without signs of being stuck means stay local.

  When either applies, lev isn't asked at all.
- **If lev is down,** the answer is *stay local* with `error` set, and the exit code is 1.
- **Eval:** `evals/escalation/seed.jsonl` has 60 drafted (task, tried) pairs with a fixed tune/test split. You
  confirm or flip each draft in the test bed (Labels → escalation). Then run
  `python3 evals/eval_escalation.py tune [--questions] [--grid]` while tuning and `… test` once.
- **Preliminary (tune split, Claude's drafted labels, not yours):**
  - lev alone 29/30;
  - rules alone 24/30;
  - rules + lev 30/30, at 0.83 lev calls per item.

  The configured question beat three alternative phrasings (28–29/30), and the threshold barely matters
  (bimodal scores). The drafts are cleaner than real agent summaries, so expect lower numbers on real ones.

## Availability

A route never points at something that can't run right now. Every check is local:

| Check | How |
|---|---|
| lev (:8200), Halogen (:8731) | Loopback `/health`. Non-loopback URLs are refused. |
| Grok Build | `grok` on PATH, and `~/.grok/auth.json` has a sign-in with a refresh token |
| Claude Code | `claude` on PATH, and `~/.claude/.credentials.json` exists (it isn't parsed) |
| OpenCode, Hermes | On PATH |
| OpenRouter | `opencode`'s auth file has an `openrouter` entry |

- **No remote calls:** nothing calls a remote or paid API, and no credential value is ever read into output. As
  a result, a revoked token still looks signed in.
- **Caching:** results are cached for 15 s and are part of the router's cache key.
- **Fallback:** a route to something that's down falls back to the next executor, and the reasons say what it fell
  back from and why.
- **Held:** text that must stay local (secrets, high-risk PII, high sensitivity) is **held** when the local model is
  down. It's never sent to a cloud model instead.
- **Config:** `router.json` → `availability`. Models and executors name what they depend on in `needs`.

## CLI

| Command | What it does | Exit codes |
|---|---|---|
| `warden scan [-b prompt\|content\|outbound] [--no-lev] [--brief]` | Run the guard (input from stdin, `-f FILE`, or args) | 0 allow · 3 review · 4 block · 1 error |
| `warden redact` | Print redacted text; counts go to stderr | 0 nothing removed · 3 redacted |
| `warden decide -q Q [-k kind] [-o id=desc …] [-l level …] [-c context] [--brief]` | One question per item (stdin lines, args, or `-f`) | |
| `warden classify [--sensitivity] [--guard] [--brief]` | Expert + mode (+ sensitivity) and the workflow they map to | 0 ok · 4 stopped by `--guard` · 1 lev down |
| `warden escalate -t TASK [TRIED \| -f FILE \| stdin] [--brief]` | Hand off to a frontier model? | 0 stay local · 3 escalate · 1 error |
| `warden route` | Experimental router; prints JSON | |
| `warden eval [--sets …] [--no-lev]` | Measure the guard | |
| `warden health [--brief]` | Check the config, lev, and what routes can use | 0 lev up · 1 lev down |
| `warden testbed` | Run the test bed UI | |

**Why a CLI and a skill, not an MCP:**
- A skill costs one description line of context until it's used; MCP tool schemas ride along with every request
  in OpenCode and Hermes.
- The same CLI serves future hooks through its exit codes.
- An MCP wrapper over these same functions can be added if a harness without a shell needs it.

## Config

`warden/defaults/guard.json` and `router.json`. To override them, copy both files to `~/.config/warden/` or point
`$WARDEN_CONFIG_DIR` at a directory. Files are re-read on every call.

## Test bed

- **Guard**: boundary picker, verdict and action, gate cards, redacted output, findings, feedback buttons, and the
  equivalent CLI command.
- **Classify**: expert and mode with probability bars, optional sensitivity and guard, plus the equivalent CLI.
- **Decide**: question, kind, options or levels, items, then results with confidence bars, plus the equivalent CLI.
- **Router (experimental)**: the live walk through the gates, agent and executors, then *Was this route right?*
  (saved as a routing label).
- **Labels**: build the routing and escalation eval sets, one item at a time with keyboard shortcuts. The model's
  prediction is never shown there, so it can't anchor the label, and labelling makes no lev calls.

Hardening:
- Loopback-only, with a Host allowlist against DNS rebinding.
- Origin check plus a required JSON content type against CSRF.
- Strict CSP; 512 KiB body cap.
- Rendering only through `textContent`.
- Request bodies are never logged.

## Layout

```
warden/          rules.py · lev.py · guard.py · classify.py · escalate.py · availability.py · decide.py · labels.py · router.py (+ router_logic.py) · evaluate.py · feedback.py · cli.py
warden/defaults/ guard.json · router.json
warden/testbed/  server.py · static/
skill/warden/    SKILL.md (not installed)
evals/           samples.json (dev) · fetch.py · analyze.py (tuning workbench) · eval_router.py · eval_routing.py · eval_escalation.py · routing/, escalation/ (seed.jsonl) · data/, reports/, cache.sqlite (git-ignored)
tests/           rules · guard · classify · escalate · availability · decide · router · labels · cli · testbed · perf (ReDoS) · fuzz (stubbed lev)
```

## Known limits

- **Allow means "no signal", not "safe".** About 17% of prompt attacks and 7% of content attacks on the test split
  get through. The real protection is sandboxing and permissions; warden is an early warning in front of them.
- **The review rate on harmless prompts is about 7%**, mostly from lev on role-play personas and
  instruction-dataset formatting. It's lower for ordinary chat.
- **Very long content is sampled:** more than 24 windows (about 12 KB). Rules still see every character.
- **lev handles one request at a time** (`-np 1`) and is shared with Sully's voice routing. Content scanning makes
  several calls per page.
- **The router's capability levels are estimates**, and it can't see attachments.
