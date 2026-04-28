# Phishing Email Detector

A command-line tool that uses Claude AI to analyse email content and identify phishing attempts with high accuracy and structured output.

```
──────────────────────────────────────────────────────────────
  Phishing Analysis Report
  Source: phishing_paypal.txt
──────────────────────────────────────────────────────────────

  VERDICT     PHISHING   🚨
  CONFIDENCE  ████████████████████████░░░░  93%

  RED FLAGS
    ▸ Sender domain "paypa1-alerts.com" typosquats PayPal
    ▸ URL points to "paypal-secure-verification.xyz", not paypal.com
    ▸ Requests SSN, CVV, and current password in one form
    ▸ 24-hour deadline creates artificial urgency
    ▸ Copyright notice uses "PayPaI" (capital I, not lowercase L)

  EXPLANATION
    Multiple high-confidence phishing indicators are present.
    The sender domain uses a digit substitution typosquat and
    the link points to a clearly unrelated domain. Legitimate
    payment processors never ask for your current password or
    Social Security Number via email.

──────────────────────────────────────────────────────────────
```

## Features

- **Structured verdict** — `PHISHING`, `SUSPICIOUS`, or `LEGITIMATE` with a calibrated confidence score
- **Red-flag enumeration** — specific indicators explained in plain language
- **Colour-coded terminal output** — red / yellow / green at a glance
- **Batch mode** — scan an entire folder and get a summary table
- **JSON reports** — machine-readable output for integration into larger pipelines or SIEM tools
- **Prompt caching** — the large expert system prompt is cached across batch calls, cutting token costs significantly
- **CI-friendly exit codes** — exits `2` when phishing is detected (safe for use in automated pipelines)

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/your-username/phishing-detector
cd phishing-detector
pip install -r requirements.txt
```

### 2. Set your API key

```bash
cp .env.example .env
# edit .env and paste your Anthropic API key
```

Or export it directly:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Run

```bash
# Analyse a single file
python detector.py --file examples/phishing_paypal.txt

# Read from stdin
cat suspicious_email.txt | python detector.py --stdin

# Batch-scan a folder and save a JSON report
python detector.py --batch examples/ --output report.json
```

## Usage

```
usage: detector [-h] (--file FILE | --stdin | --batch DIR) [--output JSON] [--no-color]

options:
  --file  FILE    path to a single email .txt file
  --stdin         read email content from stdin
  --batch DIR     analyse every .txt file in a directory
  --output JSON   write results to a JSON report file
  --no-color      disable ANSI colour output (also auto-disabled when not a TTY)
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All emails legitimate or suspicious |
| `1`  | Startup error (bad API key, file not found, …) |
| `2`  | At least one `PHISHING` verdict detected |
| `130`| Interrupted with Ctrl+C |

This makes the tool composable in shell scripts:

```bash
python detector.py --file inbox.txt || echo "⚠️  Phishing detected!"
```

## JSON Report Format

```json
{
  "generated_at": "2026-04-28T14:30:00.123456",
  "total_analysed": 3,
  "summary": {
    "PHISHING": 2,
    "SUSPICIOUS": 0,
    "LEGITIMATE": 1
  },
  "results": [
    {
      "verdict": "PHISHING",
      "confidence": 96,
      "red_flags": [
        "Sender domain typosquats a known brand",
        "Link destination does not match claimed organisation"
      ],
      "explanation": "...",
      "source": "examples/phishing_paypal.txt",
      "timestamp": "2026-04-28T14:30:00.456789"
    }
  ]
}
```

## How It Works

The tool sends each email to [Claude Haiku](https://www.anthropic.com/claude) with an expert-crafted system prompt that instructs the model to reason across ten threat categories used by real security analysts:

| Category | What is checked |
|----------|----------------|
| Urgency tactics | Artificial deadlines, account-suspension threats |
| Suspicious links | Domain mismatches, typosquats, URL shorteners |
| Impersonation | Banks, government agencies, tech companies |
| Grammar issues | Spelling errors, awkward phrasing, inconsistent formatting |
| Unusual requests | Passwords, SSNs, CVVs, gift cards, crypto |
| Sender mismatch | Display name vs. actual address, free providers impersonating corps |
| Social engineering | Fear, greed, authority exploitation |
| Technical red flags | Suspicious attachments, mismatched Reply-To, generic greetings |
| Context incongruity | Unexpected notifications, unclaimed prizes |
| Authority abuse | IT/HR/C-suite impersonation |

The system prompt is **prompt-cached** using Anthropic's caching API, so in batch mode only the first call pays the full input-token cost for the prompt — subsequent calls read it from cache at ~10% of the price.

## Requirements

- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com)
- Dependencies: `anthropic`, `python-dotenv`

## Project Structure

```
phishing-detector/
├── detector.py          # main script — CLI, API calls, output rendering
├── requirements.txt
├── .env.example         # copy to .env and add your API key
└── examples/
    ├── phishing_paypal.txt      # PayPal credential-harvesting scam
    ├── phishing_microsoft.txt   # Microsoft 365 account-takeover scam
    └── legitimate_amazon_order.txt  # real order-confirmation email
```

## Limitations & Disclaimer

- **Not a replacement for a dedicated email gateway.** This tool is designed for investigation and education, not real-time inbox filtering.
- **LLM outputs can be wrong.** Always treat results as decision support, not a final verdict. Maintain a human in the loop for consequential decisions.
- **Plain text only.** HTML emails should be converted to text before analysis (e.g., with `html2text`).

## License

MIT
