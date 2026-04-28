#!/usr/bin/env python3
"""
Phishing Email Detector — multi-provider AI backend.

Supported providers:
  openai   — OpenAI API (needs OPENAI_API_KEY)
  ollama   — local Ollama instance (no key needed)
  anthropic — Anthropic Claude (needs ANTHROPIC_API_KEY)

Usage examples:
  python detector.py --file email.txt --provider ollama --model llama3.2
  python detector.py --batch ./emails/ --provider openai --model gpt-4o-mini
  python detector.py --file email.txt --provider anthropic
"""

import argparse
import io
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# Force UTF-8 on Windows so box-drawing chars render correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ── ANSI colours ──────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def disable_colors() -> None:
    for attr in vars(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an expert cybersecurity analyst specialising in email threat detection
and social-engineering attack identification. You have analysed millions of
phishing emails and have deep expertise in the tactics used by malicious actors.

Analyse the provided email and classify it as PHISHING, LEGITIMATE, or SUSPICIOUS.

Evaluate these ten threat indicators:

1. URGENCY TACTICS — artificial time pressure, account-suspension threats,
   "act now" language, manufactured fear.
2. SUSPICIOUS LINKS — URLs that don't match the claimed sender domain,
   URL shorteners hiding destinations, typosquatted domains (e.g. paypa1.com),
   raw IP addresses as links.
3. IMPERSONATION — posing as a bank, government agency (IRS, HMRC, FBI),
   tech giant (Microsoft, Apple, Google), or known individual.
4. GRAMMAR & LANGUAGE ISSUES — spelling mistakes, awkward phrasing,
   machine-translated text, inconsistent capitalisation or formatting
   (note: sophisticated attacks may be polished).
5. UNUSUAL REQUESTS — soliciting credentials, passwords, SSNs, financial data,
   gift-card codes, wire transfers, or cryptocurrency payments.
6. SENDER MISMATCH — display name vs. actual address discrepancies;
   free providers (gmail.com, outlook.com) impersonating corporations.
7. SOCIAL ENGINEERING — exploiting fear, greed, urgency, or authority to
   bypass rational thinking; creating a false sense of trust.
8. TECHNICAL RED FLAGS — suspicious attachments (.exe, password-protected .zip),
   mismatched Reply-To addresses, generic greetings ("Dear Customer", "Dear User").
9. CONTEXT INCONGRUITY — unexpected notifications for accounts not held,
   prize winnings from contests never entered, unsolicited package alerts.
10. AUTHORITY ABUSE — claiming to be IT / HR / C-suite to compel immediate action
    without verification.

Confidence calibration:
  90-100 -> multiple clear indicators, very high certainty
  70-89  -> strong indicators present
  50-69  -> some indicators but ambiguous
  30-49  -> minimal indicators; probably legitimate but has concerns
  0-29   -> almost certainly legitimate with no notable red flags

Return ONLY valid JSON — no prose, no markdown fences, exactly this schema:
{
    "verdict":     "PHISHING" | "LEGITIMATE" | "SUSPICIOUS",
    "confidence":  <integer 0-100>,
    "red_flags":   ["<specific indicator>", ...],
    "explanation": "<2-3 sentences of concise reasoning>"
}

If the email is LEGITIMATE, red_flags must be an empty array [].
"""


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class PhishingAnalysis:
    verdict:     str
    confidence:  int
    red_flags:   list[str] = field(default_factory=list)
    explanation: str       = ""
    source:      str       = ""
    timestamp:   str       = field(default_factory=lambda: datetime.now().isoformat())


# ── Provider backends ─────────────────────────────────────────────────────────

def _parse_response(raw: str) -> PhishingAnalysis:
    """Parse JSON from model response, stripping markdown fences if present."""
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw
    data = json.loads(raw)
    return data


def _call_openai_compat(base_url: str, api_key: str, model: str, email_text: str) -> str:
    """Shared call for OpenAI and Ollama (both use openai-compatible API)."""
    try:
        from openai import OpenAI
        from httpx import Timeout
    except ImportError:
        print(f"{C.RED}Error: 'openai' package not installed. Run: pip install openai{C.RESET}",
              file=sys.stderr)
        sys.exit(1)

    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
        timeout=Timeout(connect=30, read=600, write=60, pool=30),
    )
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Analyse this email for phishing indicators:\n\n{email_text}"},
        ],
        max_tokens=1024,
        temperature=0,
    )
    return response.choices[0].message.content


def _call_anthropic(api_key: str, model: str, email_text: str) -> str:
    try:
        import anthropic
    except ImportError:
        print(f"{C.RED}Error: 'anthropic' package not installed. Run: pip install anthropic{C.RESET}",
              file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": f"Analyse this email for phishing indicators:\n\n{email_text}"},
        ],
    )
    return response.content[0].text


def analyze_email(provider: str, model: str, email_text: str, source: str = "stdin") -> PhishingAnalysis:
    if provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            print(f"{C.RED}Error: OPENAI_API_KEY is not set.{C.RESET}", file=sys.stderr)
            sys.exit(1)
        raw = _call_openai_compat("https://api.openai.com/v1", api_key, model, email_text)

    elif provider == "ollama":
        host = os.environ.get("OLLAMA_HOST", "localhost:11434")
        if not host.startswith("http"):
            host = "http://" + host
        # 0.0.0.0 is a bind address, not a valid connect target — use localhost
        host = host.replace("//0.0.0.0", "//localhost")
        base_url = host.rstrip("/") + "/v1"
        raw = _call_openai_compat(base_url, "ollama", model, email_text)

    elif provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print(f"{C.RED}Error: ANTHROPIC_API_KEY is not set.{C.RESET}", file=sys.stderr)
            sys.exit(1)
        raw = _call_anthropic(api_key, model, email_text)

    else:
        print(f"{C.RED}Error: unknown provider '{provider}'. Choose: openai, ollama, anthropic{C.RESET}",
              file=sys.stderr)
        sys.exit(1)

    data = _parse_response(raw)
    return PhishingAnalysis(
        verdict=data["verdict"],
        confidence=int(data["confidence"]),
        red_flags=data.get("red_flags", []),
        explanation=data.get("explanation", ""),
        source=source,
    )


# ── Terminal output ────────────────────────────────────────────────────────────

def _wrap(text: str, width: int = 56, indent: str = "    ") -> str:
    words, line, lines = text.split(), "", []
    for w in words:
        candidate = f"{line} {w}".strip()
        if len(candidate) > width:
            if line:
                lines.append(line)
            line = w
        else:
            line = candidate
    if line:
        lines.append(line)
    return "\n".join(f"{indent}{l}" for l in lines)


def print_analysis(analysis: PhishingAnalysis, label: str) -> None:
    if analysis.verdict == "PHISHING":
        vcol, icon = C.RED,    "PHISHING   [!!!]"
    elif analysis.verdict == "SUSPICIOUS":
        vcol, icon = C.YELLOW, "SUSPICIOUS [?]  "
    else:
        vcol, icon = C.GREEN,  "LEGITIMATE [OK] "

    bar_len = 28
    filled  = int(bar_len * analysis.confidence / 100)
    bar     = "#" * filled + "." * (bar_len - filled)
    bcol    = C.RED if analysis.confidence >= 70 else (C.YELLOW if analysis.confidence >= 40 else C.GREEN)

    div = f"{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}"
    print(f"\n{div}")
    print(f"{C.BOLD}  Phishing Analysis Report{C.RESET}")
    print(f"{C.DIM}  Source: {label}{C.RESET}")
    print(div)

    print(f"\n{C.BOLD}  VERDICT    {C.RESET}{vcol}{C.BOLD}{icon}{C.RESET}")
    print(f"{C.BOLD}  CONFIDENCE {C.RESET}{bcol}{bar}{C.RESET} {C.BOLD}{analysis.confidence}%{C.RESET}")

    print(f"\n{C.BOLD}  RED FLAGS{C.RESET}")
    if analysis.red_flags:
        for flag in analysis.red_flags:
            print(f"    {C.RED}>{C.RESET} {flag}")
    else:
        print(f"    {C.GREEN}None detected{C.RESET}")

    print(f"\n{C.BOLD}  EXPLANATION{C.RESET}")
    print(_wrap(analysis.explanation))
    print(f"\n{div}\n")


def print_batch_summary(results: list[PhishingAnalysis]) -> None:
    counts = {v: sum(1 for r in results if r.verdict == v)
              for v in ("PHISHING", "SUSPICIOUS", "LEGITIMATE")}
    div = f"{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}"
    print(div)
    print(f"{C.BOLD}  Batch Summary  —  {len(results)} emails analysed{C.RESET}")
    print(div)
    print(f"  {C.RED}{C.BOLD}Phishing   {C.RESET}{counts['PHISHING']}")
    print(f"  {C.YELLOW}{C.BOLD}Suspicious {C.RESET}{counts['SUSPICIOUS']}")
    print(f"  {C.GREEN}{C.BOLD}Legitimate {C.RESET}{counts['LEGITIMATE']}")
    print(f"{div}\n")


# ── I/O helpers ───────────────────────────────────────────────────────────────

def read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_stdin() -> str:
    print(f"{C.DIM}Reading from stdin — paste email, then press Ctrl+D (Unix) or Ctrl+Z (Windows)...{C.RESET}",
          file=sys.stderr)
    return sys.stdin.read()


def save_report(results: list[PhishingAnalysis], out: Path) -> None:
    counts = {v: sum(1 for r in results if r.verdict == v)
              for v in ("PHISHING", "SUSPICIOUS", "LEGITIMATE")}
    report = {
        "generated_at":   datetime.now().isoformat(),
        "total_analysed": len(results),
        "summary":        counts,
        "results":        [asdict(r) for r in results],
    }
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{C.CYAN}Report saved -> {out}{C.RESET}")


# ── CLI ───────────────────────────────────────────────────────────────────────

DEFAULT_MODELS = {
    "openai":    "gpt-4o-mini",
    "ollama":    "llama3.2",
    "anthropic": "claude-haiku-4-5-20251001",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detector",
        description="Phishing Email Detector — multi-provider AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
providers & required env vars:
  openai    OPENAI_API_KEY
  ollama    (none — runs locally, default http://localhost:11434)
  anthropic ANTHROPIC_API_KEY

examples:
  python detector.py --file suspicious.txt --provider ollama --model llama3.2
  python detector.py --batch ./emails/ --provider openai
  python detector.py --file email.txt --provider anthropic
  cat email.txt | python detector.py --stdin --provider ollama --model gemma3
        """,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file",  "-f", type=Path, metavar="FILE",
                     help="single email .txt file")
    src.add_argument("--stdin", "-s", action="store_true",
                     help="read email from stdin")
    src.add_argument("--batch", "-b", type=Path, metavar="DIR",
                     help="analyse every .txt file in a directory")

    parser.add_argument("--provider", "-p",
                        choices=["openai", "ollama", "anthropic"],
                        default="ollama",
                        help="AI provider (default: ollama)")
    parser.add_argument("--model", "-m", metavar="MODEL",
                        help="model name (default depends on provider)")
    parser.add_argument("--output",   "-o", type=Path, metavar="JSON",
                        help="write JSON report to file")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour output")
    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    provider = args.provider
    model    = args.model or DEFAULT_MODELS[provider]

    print(f"{C.DIM}Provider: {provider} | Model: {model}{C.RESET}", file=sys.stderr)

    results: list[PhishingAnalysis] = []

    try:
        if args.stdin:
            text     = read_stdin()
            analysis = analyze_email(provider, model, text, "stdin")
            print_analysis(analysis, "stdin")
            results.append(analysis)

        elif args.file:
            if not args.file.exists():
                print(f"{C.RED}Error: file not found — {args.file}{C.RESET}", file=sys.stderr)
                return 1
            text     = read_file(args.file)
            analysis = analyze_email(provider, model, text, str(args.file))
            print_analysis(analysis, args.file.name)
            results.append(analysis)

        else:  # --batch
            if not args.batch.is_dir():
                print(f"{C.RED}Error: not a directory — {args.batch}{C.RESET}", file=sys.stderr)
                return 1
            files = sorted(args.batch.glob("*.txt"))
            if not files:
                print(f"{C.YELLOW}No .txt files found in {args.batch}{C.RESET}", file=sys.stderr)
                return 0

            print(f"\n{C.BOLD}{C.CYAN}Starting batch scan — {len(files)} email(s)...{C.RESET}")
            for idx, f in enumerate(files, 1):
                print(f"{C.DIM}  [{idx}/{len(files)}] {f.name}{C.RESET}")
                text     = read_file(f)
                analysis = analyze_email(provider, model, text, str(f))
                print_analysis(analysis, f.name)
                results.append(analysis)

            print_batch_summary(results)

    except json.JSONDecodeError as exc:
        print(f"{C.RED}Could not parse model response as JSON: {exc}{C.RESET}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Aborted.{C.RESET}", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"{C.RED}Error: {exc}{C.RESET}", file=sys.stderr)
        return 1

    if args.output and results:
        save_report(results, args.output)

    return 2 if any(r.verdict == "PHISHING" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
