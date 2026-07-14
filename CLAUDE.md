# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

This is a zero-dependency vanilla HTML/CSS/JS app — no build step, no package manager. Open `index.html` directly in a browser or serve it with any static file server:

```
npx serve .
# or
python -m http.server 8080
```

## Architecture

The entire application is three files: `index.html` (structure), `style.css` (dark glassmorphism theme), and `main.js` (all logic).

**Providers supported:** Google Gemini, Anthropic Claude, and OpenAI. All are called directly from the browser using their respective REST APIs. The Claude calls include `anthropic-dangerous-direct-browser-access: true` to bypass the CORS restriction.

**Data flow for a single evaluation:**
1. User fills in criteria, Prompt A, Prompt B, and test case inputs
2. `runEvaluation()` loops over test cases × runs-per-test, calling `callLLM()` twice per iteration (once for Prompt A, once for Prompt B)
3. After each pair of LLM responses, `callJudge()` calls the same provider+model with a structured judge prompt that returns JSON scores/reasoning
4. Results are aggregated and rendered; the summary is saved to `localStorage` under `llm_judge_history`

**Key globals in `main.js`:**
- `PROVIDERS` — static config (models list, API URLs, localStorage key names) for each provider
- `EVAL_CRITERIA` — static array of 39 built-in evaluation criteria `{ name, description }` used to populate the criteria dropdowns
- `activeProvider`, `activeModel`, `apiKeys` — runtime state (`apiKeys` has keys for `gemini`, `claude`, `openai`); persisted to `localStorage` (encrypted)
- `judgeProvider`, `judgeModel` — separate judge model selection, persisted to `localStorage`
- `lastResults` — holds the most recent evaluation result for the Export Report feature
- `cancelRequested` — boolean flag set by the Cancel button to abort an in-progress run
- `sessionPassphrase` — passphrase held in memory only; never written to localStorage

**Criteria management:** Each criterion row uses a `<select>` populated from `EVAL_CRITERIA` (39 options) and a readonly description input that auto-fills on selection. `syncCriterionOptions()` hides already-chosen criteria from all other rows' dropdowns. `addCriterion(name, desc)` adds a row and calls `syncCriterionOptions()`; the remove handler also calls it.

**JSON parsing for judge output:** `callClaudeJson()` uses prefill (`{ role: 'assistant', content: '{' }`) to coerce JSON output; `callGeminiJson()` uses `responseMimeType: 'application/json'`; `callOpenAIJson()` uses `response_format: { type: 'json_object' }`. All three funnel through `parseJsonSafely()` which tries direct parse, then code-fence extraction, then brace-index extraction as fallbacks.

**Error handling:** `friendlyApiError(status, body)` parses raw API error responses and returns a human-readable message (e.g. "Invalid API key — please re-enter your key using the 🔑 button." instead of the raw JSON). Called by `fetchWithRetry()` before throwing.

**Persistence:** All state (API keys, provider/model selection, history up to 20 items) is in `localStorage`. No backend.

**API key security:** Keys are encrypted with AES-GCM + PBKDF2 (100 000 iterations, SHA-256) via the Web Crypto API. The passphrase is kept only in memory (`sessionPassphrase`); the salt is stored in `localStorage` under `llm_judge_salt`. Legacy plain-text keys stored before encryption was added are loaded into memory on startup and migrated on next save.

**Test suite import/export:** JSON format with fields `{ criteria, promptA, promptB, testCases[] }`. CSV import is also supported (one test case per line; header rows are auto-skipped). Criteria `name` values in imported JSON **must exactly match** an entry in `EVAL_CRITERIA` — the six bundled test suites under `test-suites/` follow this convention.

## Features

| Feature | Description |
|---|---|
| Multi-provider | Google Gemini, Anthropic Claude, and OpenAI; separate model pickers for responder and judge |
| Criteria Dropdown | 39 built-in evaluation criteria selectable from a dropdown; description auto-fills; already-chosen criteria hidden from other rows |
| Blind Mode | Labels prompts "Version 1 / 2" to the judge, eliminating positional bias |
| Custom Judge Instructions | Extra freeform instructions prepended to the judge system prompt |
| Temperature Sweep | After evaluation, charts average scores for Test Case 1 across temperatures 0–1 in 0.25 steps |
| Runs per Test Case | 1–5 repeated runs per test to measure consistency; displays a consistency bar in results |
| Prompt Versioning | Named save/restore of Prompt A and Prompt B snapshots in localStorage |
| CSV Import | Import test cases from a plain CSV or TXT file; existing cases are preserved |
| JSON Import/Export | Full test suite round-trip as `{ criteria, promptA, promptB, testCases[] }` |
| Share Setup | Encodes criteria + prompts + test cases into a URL query string |
| Share Results | Encodes full results JSON into a URL for sharing with collaborators |
| Export Report | Standalone self-contained HTML report with scores, responses, and reasoning |
| Evaluation History | Last 20 evaluations stored in localStorage; panel accessible from toolbar |
| Radar Chart | Per-criterion radar chart rendered with inline SVG when ≥3 criteria exist |
| Trend Line | Score trend across test cases rendered as an inline SVG sparkline |
| Word Diff | Inline word-level diff highlighting between Prompt A and Prompt B responses |
| Collapsible Cards | Per-test-case result cards collapse/expand on click |
| Cancel Button | Abort an in-progress evaluation cleanly without reloading |
| Keyboard Shortcuts | `Ctrl+Enter` run · `Ctrl+Shift+D` toggle theme · `Esc` close panels |
| Dark/Light Mode | Toggle stored in localStorage; respects system preference on first load |
