import os
import re
import json
import yara
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv("../.env")
API_KEY = os.getenv("GROQ_API_KEY", "")
LEGIT_DIR = "../legitimate_files"
client = OpenAI(api_key=API_KEY, base_url="https://api.groq.com/openai/v1")

scenarios = [
    "HTTP Downloader with Run registry persistence key and C2 domain",
    "UPX-packed executable (UPX0/UPX1) installing a malicious Windows service",
    "Keylogger hooking keyboard events and writing logs to AppData",
    "Dropper hiding a secondary PE payload inside the .rsrc resource section",
    "Backdoor DLL exporting installA and ServiceMain running under svchost.exe",
    "Ransomware with high section entropy (>7.5) and custom encrypted extension",
    "Credential stealer querying browser databases with a unique mutex",
    "Self-deleting Trojan spawning cmd.exe /c del"
]

SYSTEM_PROMPT = """You are a senior Detection Engineer specializing in YARA v4 signatures.
Generate a high-precision YARA rule based on the threat profile and static artifacts.
Respond EXCLUSIVELY with a valid JSON object (no text outside braces):
{
  "rule_name": "Rule_Name_Without_Spaces",
  "rationale": "Technical explanation of why these indicators minimize false positives.",
  "yara_rule": "rule Rule_Name_Without_Spaces { meta: ... strings: ... condition: uint16(0) == 0x5A4D and ... }"
}
Rules:
1. Always start the condition with: uint16(0) == 0x5A4D
2. Use unique malware artifacts (domains, mutexes, specific registry paths, dropped filenames, or UPX0/UPX1 sections).
3. Do NOT trigger on generic Windows API names alone (e.g., AdjustTokenPrivileges, LoadLibrary)."""

def sanitize_yara(raw_rule: str) -> str:
    txt = raw_rule.replace('\\n', '\n').replace('\\t', '    ').replace('\\"', '"').strip()
    def _esc(m):
        return f'"{m.group(1).replace("\\\\", "\\").replace("\\", "\\\\")}"'
    txt = re.sub(r'"([^"]*)"', _esc, txt)
    txt = re.sub(r';\s*$', '', txt, flags=re.MULTILINE)
    return txt

def check_zero_fp(compiled_rule) -> bool:
    if not os.path.exists(LEGIT_DIR):
        return True
    for fname in os.listdir(LEGIT_DIR):
        fpath = os.path.join(LEGIT_DIR, fname)
        if os.path.isfile(fpath) and compiled_rule.match(fpath):
            return False
    return True

dataset = []
total_tokens = 0

# 8 escenarios x 2 lotes de 5 = 80 ejemplos en solo 16 llamadas (~25 segundos)
for scenario in scenarios:
    for batch in range(2):
        teacher_prompt = f"""Generate a JSON object containing a list under the key "cases" with 5 distinct, realistic synthetic malware variants for: '{scenario}' (Batch {batch+1}).
        Each item in "cases" must have exact keys:
        1. "static_input": {{
             "threat_profile": {{"malware_type": "...", "risk_level": "High", "diagnosis": "...", "iocs": ["..."], "mitre_attack": [{{"Tactic": "...", "ID": "T...", "Technique": "...", "Evidence": "..."}}]}},
             "interesting_strings": ["8-12 strings mixing unique malware IoCs with decoy Windows APIs like AdjustTokenPrivileges, LookupPrivilegeValueA, SeDebugPrivilege"],
             "sections": [".text", ".rdata", ".data"]
           }}
        2. "expected_output": {{
             "rule_name": "Valid_Identifier_Name",
             "rationale": "Why these indicators were selected and why generic APIs were excluded.",
             "yara_rule": "Complete multi-line YARA v4 rule starting condition with uint16(0) == 0x5A4D, using double backslashes \\\\ in Windows paths, no semicolons, and excluding native Windows APIs."
           }}"""

        try:
            resp = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                reasoning_effort="low",
                messages=[{"role": "user", "content": teacher_prompt}],
                temperature=0.75,
                response_format={"type": "json_object"}
            )
            if hasattr(resp, "usage") and resp.usage:
                total_tokens += resp.usage.total_tokens

            data = json.loads(resp.choices[0].message.content)
            for pair in data.get("cases", []):
                try:
                    inp = pair["static_input"]
                    out = pair["expected_output"]
                    clean_rule = sanitize_yara(out["yara_rule"])
                    compiled = yara.compile(source=clean_rule)
                    if check_zero_fp(compiled):
                        out["yara_rule"] = clean_rule
                        dataset.append({
                            "messages": [
                                {"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": json.dumps(inp, indent=2)},
                                {"role": "assistant", "content": json.dumps(out, ensure_ascii=False)}
                            ]
                        })
                except Exception:
                    continue  # Descarta solo el ejemplo defectuoso y salva el resto del lote
            print(f"[{scenario[:25]}...] Verified total: {len(dataset)} | Tokens: {total_tokens:,}")
        except Exception as e:
            print(f"API error: {e}")

with open("yara_dataset.jsonl", "w", encoding="utf-8") as f:
    for item in dataset:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print(f"\nDone! Saved {len(dataset)} verified examples ({total_tokens:,} tokens used).")