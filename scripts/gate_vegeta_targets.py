#!/usr/bin/env python3
"""Write a vegeta targets file for the gate's /check endpoint.

Same request mix as the gate_load example (complete browsers, bare browsers,
HTTP libraries, a self-declared agent, garbage Web Bot Auth signatures) from
many distinct X-Forwarded-For addresses, so an independent load tool can
cross-check the in-repo generator:

    python3 scripts/gate_vegeta_targets.py targets.txt
    vegeta attack -targets=targets.txt -rate=5000 -duration=60s -keepalive | vegeta report
"""

import random
import sys

URL = "http://127.0.0.1:9091/check"
CHROME = (
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)
BROWSER = [
    CHROME,
    "Accept-Language: en-US,en;q=0.9",
    "Sec-Fetch-Site: none",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-Dest: document",
]
# (share in percent, headers)
PROFILES = [
    (60, BROWSER),
    (10, [CHROME.replace("142", "139")]),
    (10, ["User-Agent: curl/8.5.0"]),
    (5, ["User-Agent: python-requests/2.32.3"]),
    (5, []),
    (5, ["User-Agent: Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"]),
    (5, [
        CHROME,
        'Signature-Agent: "https://example.com"',
        'Signature-Input: sig1=("@authority" "signature-agent");created=1735690000;keyid="abc";alg="ed25519";expires=1735693600;nonce="n";tag="web-bot-auth"',
        "Signature: sig1=:" + "A" * 86 + "=:",
    ]),
]


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "targets.txt"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 300_000
    clients = int(sys.argv[3]) if len(sys.argv) > 3 else 300_000
    rng = random.Random(7)
    weights = [p[0] for p in PROFILES]
    with open(out, "w", encoding="utf-8") as f:
        for _ in range(count):
            ip = rng.randrange(clients)
            f.write(f"GET {URL}\n")
            f.write(f"X-Forwarded-For: 10.{(ip >> 16) & 255}.{(ip >> 8) & 255}.{ip & 255}\n")
            f.write("X-Forwarded-Method: GET\nX-Forwarded-Uri: /\n")
            f.write("X-Forwarded-Host: www.example.com\nX-Forwarded-Proto: https\n")
            for header in rng.choices(PROFILES, weights)[0][1]:
                f.write(header + "\n")
            f.write("\n")
    print(f"{count} targets over {clients} clients written to {out}")


if __name__ == "__main__":
    main()
