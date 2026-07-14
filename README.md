# LLM Judge — Prompt A/B Evaluator

A zero-dependency, browser-only tool for comparing two LLM prompts side-by-side using automated AI-powered scoring. Supports Google Gemini, Anthropic Claude, and OpenAI. No backend, no build step, no sign-up.

## Quick Start

Open `index.html` directly in your browser, or serve with any static file server:

```bash
npx serve .
# or
python -m http.server 8080
```

Enter your API key on first launch and start evaluating immediately.

## How It Works

1. **Define criteria** — Pick from 39 built-in evaluation dimensions (e.g. "Accuracy", "Clarity", "Code Quality"). The description auto-fills so you know exactly what the judge is measuring. Each criterion is scored 0–10.
2. **Write two prompts** — Paste your baseline system prompt as Prompt A and your revised version as Prompt B.
3. **Add test cases** — Provide user messages that both prompts will receive.
4. **Run** — The tool calls the LLM twice per test case (once per prompt), then calls a judge model to score both responses against every criterion.
5. **Review results** — Scores, reasoning, and comparisons are displayed inline. A radar chart and trend line summarise overall performance.

## Supported Providers

| Provider | Models |
|---|---|
| Google Gemini | gemini-2.0-flash, gemini-1.5-flash, gemini-1.5-pro |
| Anthropic Claude | claude-haiku-4-5, claude-sonnet-4, claude-opus-4 |
| OpenAI | gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo |

You can use a different model as the **judge** than the one generating responses — recommended to reduce self-evaluation bias.

## Features

### Evaluation
- **Multi-criterion scoring** — choose from 39 built-in criteria; descriptions auto-fill; already-selected criteria are hidden from other rows to prevent duplicates
- **Runs per test case** — run 1–5 times per test case to measure consistency
- **Blind Mode** — labels prompts "Version 1" and "Version 2" to the judge to remove positional bias
- **Custom Judge Instructions** — prepend extra instructions to the judge system prompt (e.g. "Prioritise conciseness")
- **Temperature Sweep** — after evaluation, charts scores for Test Case 1 across temperatures 0, 0.25, 0.5, 0.75, 1.0
- **Cancel** — abort an in-progress evaluation at any time

### Results & Visualisation
- **Radar chart** — per-criterion comparison when 3+ criteria are defined
- **Trend line** — score trend across test cases
- **Word diff** — inline word-level diff between Prompt A and Prompt B responses
- **Collapsible cards** — expand/collapse individual test case results

### Sharing & Export
- **Share Setup** — encodes criteria, prompts, and test cases into a shareable URL
- **Share Results** — encodes full evaluation results into a URL
- **Export Report** — generates a standalone self-contained HTML file with all scores, responses, and reasoning
- **Import/Export test suite** — JSON format (`{ criteria, promptA, promptB, testCases[] }`); six ready-made suites included in `test-suites/`
- **CSV Import** — import test cases from a plain `.csv` or `.txt` file (one per line; header rows auto-skipped)

### Prompt Management
- **Prompt Versioning** — save named snapshots of Prompt A and Prompt B and restore them later
- **Evaluation History** — last 20 evaluations stored locally; accessible from the toolbar

### Security
API keys are encrypted at rest using **AES-GCM + PBKDF2** (100 000 iterations, SHA-256) via the browser's Web Crypto API. The passphrase is never written to disk — only kept in memory for the session.

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Enter` | Run evaluation |
| `Ctrl+Shift+D` | Toggle dark/light mode |
| `Esc` | Close open panels |

## Architecture

Three files, no dependencies:

| File | Purpose |
|---|---|
| `index.html` | App structure and all UI markup |
| `style.css` | Dark glassmorphism theme with light-mode overrides |
| `main.js` | All application logic |

All state is persisted to `localStorage`. There is no backend, no network calls except to the AI provider APIs, and no analytics.

## API Keys

- **Google Gemini** — get a free key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
- **Anthropic Claude** — get a key at [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
- **OpenAI** — get a key at [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
