# Phishing Email Detector

A command-line tool that uses AI to analyse email content and identify phishing attempts with structured output. Supports **OpenAI**, **Ollama (local)**, and **Anthropic Claude** as backends — no vendor lock-in.

```
────────────────────────────────────────────────────────────
  Phishing Analysis Report
  Source: phishing_paypal.txt
────────────────────────────────────────────────────────────

  VERDICT    PHISHING   [!!!]
  CONFIDENCE ###########################. 97%

  RED FLAGS
    > URGENCY TACTICS
    > SUSPICIOUS LINKS
    > IMPERSONATION
    > UNUSUAL REQUESTS
    > SENDER MISMATCH

  EXPLANATION
    The email uses urgency tactics, a suspicious link,
    impersonates PayPal with a typo in the domain, requests
    sensitive information, and has a mismatched sender address.

────────────────────────────────────────────────────────────
```

## Features

- **Multi-provider** — OpenAI, Ollama (local models), or Anthropic Claude
- **Structured verdict** — `PHISHING`, `SUSPICIOUS`, or `LEGITIMATE` with a calibrated confidence score
- **Red-flag enumeration** — specific indicators explained in plain language
- **Colour-coded terminal output** — red / yellow / green at a glance
- **Batch mode** — scan an entire folder and get a summary table
- **JSON reports** — machine-readable output for SIEM integration
- **CI-friendly exit codes** — exits `2` when phishing is detected

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/PolskiLisek11/phishing-detector
cd phishing-detector
pip install -r requirements.txt
```

### 2. Pick a provider

#### Ollama (local, free)

Install [Ollama](https://ollama.com), pull a model, start the server:

```bash
ollama pull qwen2.5:14b
ollama serve
```

Run the detector:

```bash
python detector.py --file examples/phishing_paypal.txt --provider ollama --model qwen2.5:14b
```

No API key needed.

#### OpenAI

```bash
export OPENAI_API_KEY=sk-...
python detector.py --file examples/phishing_paypal.txt --provider openai
# default model: gpt-4o-mini
```

#### Anthropic Claude

```bash
export ANTHROPIC_API_KEY=sk-ant-...
pip install anthropic
python detector.py --file examples/phishing_paypal.txt --provider anthropic
# default model: claude-haiku-4-5-20251001
```

## Usage

```
usage: detector [-h] (--file FILE | --stdin | --batch DIR)
                [--provider {openai,ollama,anthropic}] [--model MODEL]
                [--output JSON] [--no-color]

options:
  --file FILE      path to a single email .txt file
  --stdin          read email content from stdin
  --batch DIR      analyse every .txt file in a directory
  --provider       AI provider: openai | ollama | anthropic  (default: ollama)
  --model          model name (defaults per provider listed below)
  --output JSON    write results to a JSON report file
  --no-color       disable ANSI colour output
```

### Default models

| Provider | Default model |
|----------|--------------|
| `ollama` | `llama3.2` |
| `openai` | `gpt-4o-mini` |
| `anthropic` | `claude-haiku-4-5-20251001` |

Pass `--model` to override, e.g. `--model qwen2.5:14b` or `--model gpt-4o`.

### Examples

```bash
# Batch scan with Ollama, save JSON report
python detector.py --batch examples/ --provider ollama --model qwen2.5:14b --output report.json

# Pipe email from stdin using OpenAI
cat suspicious.txt | python detector.py --stdin --provider openai

# No colour output (e.g. for logging)
python detector.py --file email.txt --provider ollama --no-color | tee scan.log
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All emails legitimate or suspicious |
| `1`  | Startup error (bad key, file not found, …) |
| `2`  | At least one `PHISHING` verdict detected |
| `130`| Interrupted with Ctrl+C |

```bash
python detector.py --file inbox.txt --provider ollama || echo "Phishing detected!"
```

## JSON Report Format

```json
{
  "generated_at": "2026-04-28T14:30:00.123456",
  "total_analysed": 3,
  "summary": { "PHISHING": 2, "SUSPICIOUS": 1, "LEGITIMATE": 0 },
  "results": [
    {
      "verdict": "PHISHING",
      "confidence": 97,
      "red_flags": ["Sender domain typosquats PayPal", "..."],
      "explanation": "...",
      "source": "examples/phishing_paypal.txt",
      "timestamp": "2026-04-28T14:30:00.456789"
    }
  ]
}
```

## How It Works

The tool sends each email to the selected AI model with an expert-crafted system prompt that evaluates ten threat categories used by real security analysts:

| Category | What is checked |
|----------|----------------|
| Urgency tactics | Artificial deadlines, account-suspension threats |
| Suspicious links | Domain mismatches, typosquats, URL shorteners |
| Impersonation | Banks, government agencies, tech companies |
| Grammar issues | Spelling errors, awkward phrasing |
| Unusual requests | Passwords, SSNs, CVVs, gift cards, crypto |
| Sender mismatch | Display name vs. actual address |
| Social engineering | Fear, greed, authority exploitation |
| Technical red flags | Suspicious attachments, generic greetings |
| Context incongruity | Unexpected notifications, unclaimed prizes |
| Authority abuse | IT/HR/C-suite impersonation |

## Requirements

- Python 3.11+
- At least one provider package:
  - `openai` — for OpenAI and Ollama
  - `anthropic` — for Anthropic Claude
- `python-dotenv` (optional, for `.env` file support)

## Project Structure

```
phishing-detector/
├── detector.py              # main script — CLI, providers, output rendering
├── requirements.txt
├── .env.example             # template for API keys
└── examples/
    ├── phishing_paypal.txt
    ├── phishing_microsoft.txt
    └── legitimate_amazon_order.txt
```

## Limitations & Disclaimer

- **Not a replacement for a dedicated email gateway.** Designed for investigation and education, not real-time inbox filtering.
- **LLM outputs can be wrong.** Treat results as decision support, not a final verdict.
- **Plain text only.** Convert HTML emails before analysis (e.g. with `html2text`).

## License

MIT
