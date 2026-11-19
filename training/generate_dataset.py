import os
import re
import json
import time
import yara
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv("../.env")
os.environ["OPENAI_BASE_URL"] = "https://api.groq.com/openai/v1"

api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise RuntimeError("No GROQ_API_KEY in ../.env")

client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

OUTPUT_FILE = "yara_dataset_v2.jsonl"
LEGIT_DIR = "../legitimate_files"

SCENARIOS = [
    "UPX-packed service downloader using WinINet and CreateServiceA",
    "Process injector using VirtualAllocEx, WriteProcessMemory and CreateRemoteThread",
    "Credential stealer querying LSASS and browser SQLite databases",
    "Ransomware encrypting user directories and deleting shadow copies via vssadmin",
    "Registry Run-key persistence dropper with embedded PE resource",
    "Reverse shell backdoor connecting via WSAStartup and connect",
    "Keylogger hooking keyboard events via SetWindowsHookExA",
    "Scheduled task persistence loader using schtasks and PowerShell",
    "DLL sideloading proxy exporting legitimate functions",
    "WMI lateral movement dropper with high-entropy .data section"
]

SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer. Output ONLY valid JSON with keys "
    "'rule_name', 'yara_rule', and 'rationale'. Write strict YARA v4 rules combining "
    "PE header checks (uint16(0) == 0x5A4D), 'import \"pe\"' (pe.imports), 'import \"math\"' "
    "(math.entropy when packed), and '2 of ($s*)' over unique strings (never DOS stub or generic DLL names)."
)

def passes_audit(rule_text: str) -> bool:
    try:
        compiled = yara.compile(source=rule_text)
        if os.path.exists(LEGIT_DIR):
            for f in os.listdir(LEGIT_DIR):
                fp = os.path.join(LEGIT_DIR, f)
                if os.path.isfile(fp) and compiled.match(fp):
                    return False
        return True
    except Exception:
        return False

dataset = []
for sc in SCENARIOS:
    for batch in range(6):
        prompt = f"""Generate 2 distinct training pairs for malware scenario: '{sc}' (variant {batch+1}).
Respond ONLY with raw JSON (no markdown fences) with a single key "examples" containing 2 objects:
{{
  "examples": [
    {{
      "input": {{"threat_profile": {{"malware_type": "...", "risk_level": "High"}}, "possible_packing": true, "max_entropy": 7.45, "imports_dll": {{"DLL": ["API1", "API2"]}}, "interesting_strings": ["3 unique IoCs", "This program cannot be run in DOS mode.", "KERNEL32.dll"], "sections": [".text", "UPX0", "UPX1"]}},
      "output": {{"rule_name": "...", "yara_rule": "import \\"pe\\"\\nimport \\"math\\"\\n\\nrule Example_Rule {{\\n    meta:\\n        description = \\"...\\"\\n    strings:\\n        $s1 = \\"...\\" ascii wide\\n        $s2 = \\"...\\" ascii wide\\n    condition:\\n        uint16(0) == 0x5A4D and math.entropy(0, filesize) >= 6.8 and pe.imports(\\"DLL\\", \\"API1\\") and 2 of ($s*)\\n}}", "rationale": "..."}}
    }}
  ]
}}"""
        try:
            resp = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=4096
            )
            raw = resp.choices[0].message.content
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if not m:
                continue
            items = json.loads(m.group(0)).get("examples", [])
            for ex in items:
                rule = ex.get("output", {}).get("yara_rule", "")
                if "uint16(0) == 0x5A4D" in rule and passes_audit(rule):
                    dataset.append({
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": json.dumps(ex["input"])},
                            {"role": "assistant", "content": json.dumps(ex["output"], ensure_ascii=False)}
                        ]
                    })
        except Exception as e:
            print(f"Warning in batch {batch+1} of '{sc}': {e}")
            time.sleep(2)
    print(f"Progress: {len(dataset)} valid examples...")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for row in dataset:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
print(f"Dataset ready: {OUTPUT_FILE} ({len(dataset)} examples)")