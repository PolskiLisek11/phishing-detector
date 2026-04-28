#!/usr/bin/env python3
"""
Phishing Email Detector — powered by Claude Haiku AI.

Accepts email text via file, stdin, or batch directory and returns a
structured analysis: verdict, confidence, red flags, and explanation.
"""

import anthropic
import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

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


# ── Expert system prompt (cached across batch runs) ───────────────────────────

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
  90-100 → multiple clear indicators, very high certainty
  70-89  → strong indicators present
  50-69  → some indicators but ambiguous
  30-49  → minimal indicators; probably legitimate but has concerns
  0-29   → almost certainly legitimate with no notable red flags

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


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze_email(
    client: anthropic.Anthropic,
    email_text: str,
    source: str = "stdin",
) -> PhishingAnalysis:
    """Call Claude Haiku with the email text and parse the structured response."""
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                # Cache the large system prompt — saves tokens on every batch call.
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": f"Analyse this email for phishing indicators:\n\n{email_text}",
            }
        ],
    )

    raw = response.content[0].text.strip()

    # Strip markdown code fences if the model wraps output in them.
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw

    data = json.loads(raw)

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
    """Render a colour-coded analysis block to stdout."""
    if analysis.verdict == "PHISHING":
        vcol, icon = C.RED,    "PHISHING   🚨"
    elif analysis.verdict == "SUSPICIOUS":
        vcol, icon = C.YELLOW, "SUSPICIOUS ⚠️ "
    else:
        vcol, icon = C.GREEN,  "LEGITIMATE ✅"

    bar_len = 28
    filled  = int(bar_len * analysis.confidence / 100)
    bar     = "█" * filled + "░" * (bar_len - filled)
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
            print(f"    {C.RED}▸{C.RESET} {flag}")
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
    print(f"{C.DIM}Reading from stdin — paste email, then press Ctrl+D (Unix) or Ctrl+Z (Windows)…{C.RESET}",
          file=sys.stderr)
    return sys.stdin.read()


def save_report(results: list[PhishingAnalysis], out: Path) -> None:
    counts = {v: sum(1 for r in results if r.verdict == v)
              for v in ("PHISHING", "SUSPICIOUS", "LEGITIMATE")}
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_analysed": len(results),
        "summary": counts,
        "results": [asdict(r) for r in results],
    }
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{C.CYAN}Report saved → {out}{C.RESET}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detector",
        description="Phishing Email Detector — powered by Claude AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  detector --file suspicious.txt
  detector --stdin < email.txt
  cat email.txt | detector --stdin
  detector --batch ./emails/ --output report.json
  detector --batch ./emails/ --no-color | tee scan.log
        """,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file",  "-f", type=Path, metavar="FILE",
                     help="path to a single email .txt file")
    src.add_argument("--stdin", "-s", action="store_true",
                     help="read email content from stdin")
    src.add_argument("--batch", "-b", type=Path, metavar="DIR",
                     help="analyse every .txt file in a directory")

    parser.add_argument("--output",   "-o", type=Path, metavar="JSON",
                        help="write a JSON report to this file")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour output")
    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print(f"{C.RED}Error: ANTHROPIC_API_KEY is not set.\n"
              f"Copy .env.example → .env and add your key.{C.RESET}", file=sys.stderr)
        return 1

    client  = anthropic.Anthropic(api_key=api_key)
    results: list[PhishingAnalysis] = []

    try:
        if args.stdin:
            text     = read_stdin()
            analysis = analyze_email(client, text, "stdin")
            print_analysis(analysis, "stdin")
            results.append(analysis)

        elif args.file:
            if not args.file.exists():
                print(f"{C.RED}Error: file not found — {args.file}{C.RESET}", file=sys.stderr)
                return 1
            text     = read_file(args.file)
            analysis = analyze_email(client, text, str(args.file))
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

            print(f"\n{C.BOLD}{C.CYAN}Starting batch scan — {len(files)} email(s)…{C.RESET}")
            for idx, f in enumerate(files, 1):
                print(f"{C.DIM}  [{idx}/{len(files)}] {f.name}{C.RESET}")
                text     = read_file(f)
                analysis = analyze_email(client, text, str(f))
                print_analysis(analysis, f.name)
                results.append(analysis)

            print_batch_summary(results)

    except anthropic.AuthenticationError:
        print(f"{C.RED}Error: invalid API key.{C.RESET}", file=sys.stderr)
        return 1
    except anthropic.RateLimitError:
        print(f"{C.RED}Error: rate limit exceeded — wait and retry.{C.RESET}", file=sys.stderr)
        return 1
    except anthropic.APIError as exc:
        print(f"{C.RED}API error: {exc}{C.RESET}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"{C.RED}Could not parse Claude response as JSON: {exc}{C.RESET}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Aborted.{C.RESET}", file=sys.stderr)
        return 130

    if args.output and results:
        save_report(results, args.output)

    # Non-zero exit when phishing detected — useful for CI pipelines.
    return 2 if any(r.verdict == "PHISHING" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
