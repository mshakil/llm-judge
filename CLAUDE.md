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

**Providers supported:** Google Gemini and Anthropic Claude. Both are called directly from the browser using their respective REST APIs. The Claude calls include `anthropic-dangerous-direct-browser-access: true` to bypass the CORS restriction.

**Data flow for a single evaluation:**
1. User fills in criteria, Prompt A, Prompt B, and test case inputs
2. `runEvaluation()` loops over test cases × runs-per-test, calling `callLLM()` twice per iteration (once for Prompt A, once for Prompt B)
3. After each pair of LLM responses, `callJudge()` calls the same provider+model with a structured judge prompt that returns JSON scores/reasoning
4. Results are aggregated and rendered; the summary is saved to `localStorage` under `llm_judge_history`

**Key globals in `main.js`:**
- `PROVIDERS` — static config (models list, API URLs, localStorage key names) for each provider
- `activeProvider`, `activeModel`, `apiKeys` — runtime state, persisted to `localStorage`
- `lastResults` — holds the most recent evaluation result for the Export Report feature

**JSON parsing for judge output:** `callClaudeJson()` uses prefill (`{ role: 'assistant', content: '{' }`) to coerce JSON output; `callGeminiJson()` uses `responseMimeType: 'application/json'`. Both funnel through `parseJsonSafely()` which tries direct parse, then code-fence extraction, then brace-index extraction as fallbacks.

**Persistence:** All state (API keys, provider/model selection, history up to 20 items) is in `localStorage`. No backend.

**Test suite import/export:** JSON format with fields `{ criteria, promptA, promptB, testCases[] }`.
