import os
import re
import json
import time
import yara
from openai import OpenAI

YARA_SYSTEM_PROMPT = (
    "You are an expert YARA v4 detection engineer. Given static PE artifacts and a threat profile, "
    "generate a zero-false-positive YARA v4 rule. Respond ONLY with valid JSON: "
    '{"rule_name": "...", "rationale": "...", "yara_rule": "..."}'
)


def sanitize_and_format_yara(raw_rule: str) -> str:
    txt = raw_rule.replace("\\n", "\n").replace("\\t", "    ").replace('\\"', '"').strip()

    if txt.count("\n") < 4:
        txt = re.sub(r"\s*\{\s*", " {\n    ", txt, count=1)
        txt = re.sub(r"\s*(meta|strings|condition)\s*:\s*", r"\n\n    \1:\n        ", txt)
        txt = re.sub(r"\s+(\$[a-zA-Z0-9_]+\s*=)", r"\n        \1", txt)
        txt = re.sub(r'"\s+([a-zA-Z0-9_]+\s*=)', r'"\n        \1', txt)
        txt = re.sub(r"\s*\}\s*$", "\n}", txt)

    def _escape_backslashes(match):
        content = match.group(1)
        clean_content = content.replace("\\\\", "\\").replace("\\", "\\\\")
        return f'"{clean_content}"'

    txt = re.sub(r'"([^"]*)"', _escape_backslashes, txt)
    txt = re.sub(r";\s*$", "", txt, flags=re.MULTILINE)
    txt = re.sub(r'^\s*[a-zA-Z0-9_]+\s*=\s*\[.*?\]\s*$', '', txt, flags=re.MULTILINE | re.DOTALL)
    return txt


def generate_and_validate_yara(
    provider: str,
    api_key: str,
    model: str,
    profile: dict,
    pe_data: dict,
    exe_bytes: bytes,
    legit_dir: str,
    samples_dir: str
) -> dict:
    t0 = time.time()

    if provider == "Local (Ollama)":
        client = OpenAI(api_key="ollama", base_url="http://localhost:11434/v1")
    else:
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

    clean_profile = {
    "malware_type": str(profile.get("malware_type", "Malware")),
    "risk_level": str(profile.get("risk_level", "High"))
}

    context = {
        "threat_profile": clean_profile,
        "interesting_strings": [s[:60] for s in pe_data["interesting_strings"][:15]],
        "sections": [s["Section"] for s in pe_data["sections"]]
    }

    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": YARA_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(context)}
        ],
        "temperature": 0.1,
        "max_tokens": 500
    }
    if provider == "Local (Ollama)":
        kwargs["extra_body"] = {
            "keep_alive": "2m",
            "options": {"num_ctx": 2048}
        }

    resp = client.chat.completions.create(**kwargs)
    raw_content = resp.choices[0].message.content

    try:
        match_json = re.search(r"\{.*\}", raw_content, re.DOTALL)
        data = json.loads(match_json.group(0))
    except Exception:
        return {
            "rule_name": "LLM_Format_Error",
            "rationale": "Model output did not conform to valid JSON structure.",
            "yara_rule": raw_content,
            "compiles": False,
            "syntax_error": "Invalid JSON formatting in model response",
            "target_match": False,
            "offsets": [],
            "fps": 0,
            "legit_table": [],
            "samples_table": [],
            "elapsed_time": round(time.time() - t0, 2)
        }

    rule_name = data.get("rule_name") or data.get("nombre_regla") or "YARA_Rule"
    rationale = data.get("rationale") or data.get("explicacion") or ""
    raw_yara = data.get("yara_rule") or data.get("regla_yara") or ""
    rule_str = sanitize_and_format_yara(raw_yara)

    res = {
        "rule_name": rule_name,
        "rationale": rationale,
        "yara_rule": rule_str,
        "compiles": False,
        "syntax_error": "",
        "target_match": False,
        "offsets": [],
        "fps": 0,
        "legit_table": [],
        "samples_table": [],
        "elapsed_time": round(time.time() - t0, 2)
    }

    try:
        compiled_rule = yara.compile(source=rule_str)
        res["compiles"] = True
    except yara.SyntaxError as e:
        res["syntax_error"] = str(e)
        return res

    hits = compiled_rule.match(data=exe_bytes)
    if hits:
        res["target_match"] = True
        for m in hits:
            for s in m.strings:
                for inst in s.instances:
                    res["offsets"].append({
                        "YARA Identifier": s.identifier,
                        "Binary Offset": hex(inst.offset),
                        "Matched String": inst.matched_data.decode("utf-8", errors="replace")[:70]
                    })

    if os.path.exists(legit_dir):
        for f in sorted(os.listdir(legit_dir)):
            path = os.path.join(legit_dir, f)
            if os.path.isfile(path):
                alerta = bool(compiled_rule.match(path))
                if alerta:
                    res["fps"] += 1
                res["legit_table"].append({
                    "Benign Binary": f,
                    "Status": "FALSE POSITIVE" if alerta else "CLEAN"
                })

    if os.path.exists(samples_dir):
        for f in sorted(os.listdir(samples_dir)):
            path = os.path.join(samples_dir, f)
            if os.path.isfile(path):
                alerta = bool(compiled_rule.match(path))
                res["samples_table"].append({
                    "Lab Sample": f,
                    "Status": "DETECTED" if alerta else "NO MATCH"
                })

    return res