"""Did the take-home brief itself try to inject instructions into me?

This exercise is about treating retrieved content as untrusted data. The brief arrived as a PDF
that I fed to a text extractor and then read, which makes the brief itself a piece of
attacker-influenceable content in exactly the sense the exercise is about. So before building
anything, I checked it — because "I only trust documents from people I trust" is precisely the
assumption prompt injection exploits.

The specific thing being looked for is text a human reader cannot see but an extractor picks up.
Drawing text in white on a white page is the classic trick: `pdftotext` yields it verbatim, the
reader never knows it was there, and anything reading the extracted text treats it as part of the
instructions.

    python verify_brief_not_injected.py

Findings for "Senior_Regulated_AI_Action_Workflow_Engine 3.pdf" (clean):

  * No active content:   /JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile, /Annots, /AA
                         and /RichMedia all appear zero times.
  * No invisible text:   3 of 172 text-draw operations use a white fill, and all three are the
                         evaluation table's header row ("Category", "Points", "What we are
                         looking for") painted white on its dark blue band. Visible to a reader.
  * No micro-text:       smallest font size is 8.04pt.
  * No planted prose:    the only instruction-shaped phrases in the text are the brief's own
                         requirements about handling a malicious evidence snippet.

Kept in the repository deliberately. The habit it represents is the point of the exercise, and it
is the same reasoning as PromptInjectionScanner: screen untrusted content at the boundary where it
enters, and record what you found.
"""
import re
import sys
import zlib

DEFAULT_PDF = "Senior_Regulated_AI_Action_Workflow_Engine 3.pdf"

# Features that would let a PDF do something rather than merely say something.
ACTIVE_CONTENT_KEYS = [
    b"/JS",
    b"/JavaScript",
    b"/OpenAction",
    b"/Launch",
    b"/EmbeddedFile",
    b"/Annots",
    b"/AA",
    b"/RichMedia",
]

# Text-show operators, and the fill-colour operators that decide whether the text is visible.
TOKEN = re.compile(
    rb"(\[.*?\]\s*TJ"                    # array form:  [(text) -12 (more)] TJ
    rb"|\(.*?\)\s*Tj"                    # simple form: (text) Tj
    rb"|[\d.]+\s+[\d.]+\s+[\d.]+\s+rg"   # RGB fill colour
    rb"|[\d.]+\s+g)",                    # greyscale fill colour
    re.S,
)

# A PDF string literal, allowing escaped characters and rejecting bare parentheses.
LITERAL = re.compile(rb"\((?:\\.|[^()\\])*\)", re.S)

WHITE_THRESHOLD = 0.95


def content_streams(data: bytes) -> list[bytes]:
    """Every stream in the file, inflated where it is Flate-compressed."""
    streams = []
    for raw in re.findall(rb"stream\r?\n(.*?)endstream", data, re.S):
        try:
            streams.append(zlib.decompress(raw))
        except zlib.error:
            # Not Flate-compressed, or an image. Either way, not prose.
            continue
    return streams


def shown_text(operator: bytes) -> bytes:
    """The characters a text-show operator actually paints."""
    return b"".join(match.group(0)[1:-1] for match in LITERAL.finditer(operator))


def is_white(colour_operator: bytes) -> bool:
    components = [float(n) for n in re.findall(rb"[\d.]+", colour_operator)]
    return bool(components) and all(c > WHITE_THRESHOLD for c in components)


def main(path: str) -> int:
    with open(path, "rb") as handle:
        data = handle.read()

    print(f"{path}  ({len(data):,} bytes)\n")

    print("Active content")
    for key in ACTIVE_CONTENT_KEYS:
        count = data.count(key)
        flag = "  <-- present" if count else ""
        print(f"  {key.decode():14} {count}{flag}")

    invisible: list[bytes] = []
    total = 0
    font_sizes: set[str] = set()

    for stream in content_streams(data):
        font_sizes.update(size.decode() for size in re.findall(rb"/\w+ ([\d.]+) Tf", stream))

        colour_is_white = False
        for match in TOKEN.finditer(stream):
            operator = match.group(1)

            if operator.rstrip().endswith(b"rg") or operator.rstrip().endswith(b"g"):
                colour_is_white = is_white(operator)
                continue

            text = shown_text(operator)
            if not text.strip():
                continue

            total += 1
            if colour_is_white:
                invisible.append(text)

    print(f"\nText drawn in white: {len(invisible)} of {total} text-show operations")
    for text in invisible:
        print(f"  {text.decode('latin-1')[:140]!r}")

    if font_sizes:
        print(f"\nFont sizes in use: {sorted(font_sizes, key=float)}")

    # White text is not automatically malicious — it is how you label a dark table header — so the
    # output is for a human to read rather than a pass/fail the script decides.
    print("\nReview the white-drawn strings above: legitimate uses are headings on dark bands.")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PDF))
