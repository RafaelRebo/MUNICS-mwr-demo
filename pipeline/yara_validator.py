import os
import re
import json
import time
import yara
from openai import OpenAI

YARA_SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer. Output ONLY valid JSON with keys "
    "'rule_name', 'yara_rule', and 'rationale'. Write strict YARA v4 rules combining "
    "PE header checks (uint16(0) == 0x5A4D), 'import \"pe\"' (pe.imports), 'import \"math\"' "
    "(math.entropy when packed), and '2 of ($s*)' over unique strings (never DOS stub or generic DLL names)."
)


def _expand_multiline(txt: str) -> str:
    if txt.count("\n") < 4:
        txt = re.sub(r'(import\s+"[^"]+"\s*)', r"\1\n", txt)
        txt = re.sub(r"\s*\{\s*", " {\n    ", txt, count=1)
        txt = re.sub(r"\s*(meta|strings|condition)\s*:\s*", r"\n\n    \1:\n        ", txt)
        txt = re.sub(r"\s+(\$[a-zA-Z0-9_]+\s*=)", r"\n        \1", txt)
        txt = re.sub(r'"\s+([a-zA-Z0-9_]+\s*=)', r'"\n        \1', txt)
        txt = re.sub(r"\s*\}\s*$", "\n}", txt)
    return txt


def sanitize_and_format_yara(raw_rule: str, is_packed: bool = False) -> str:
    txt = raw_rule.replace("\\n", "\n").replace("\\t", "    ").replace('\\"', '"').strip()

    # Strip markdown fences or text before 'import ' / 'rule '
    lines = txt.splitlines()
    cleaned_lines = []
    started = False
    for line in lines:
        s = line.strip()
        if s.startswith("```"):
            continue
        if s.startswith("import ") or s.startswith("rule "):
            started = True
        if started:
            cleaned_lines.append(line)
    txt = "\n".join(cleaned_lines).strip()

    if not txt:
        # Fallback: format raw output cleanly in multiple lines so broken rules are still readable
        txt = re.sub(r"```[a-zA-Z]*\n?", "", raw_rule).replace("```", "").strip()
        return _expand_multiline(txt)

    # Expand single-line rules while preserving top-level import statements
    txt = _expand_multiline(txt)

    def _escape_backslashes(match):
        content = match.group(1)
        clean_content = content.replace("\\\\", "\\").replace("\\", "\\\\")
        return f'"{clean_content}"'

    # Escape backslashes inside string literals without breaking import "pe" / import "math"
    txt = re.sub(r'"([^"]*)"', _escape_backslashes, txt)
    txt = re.sub(r";\s*$", "", txt, flags=re.MULTILINE)
    txt = re.sub(r'^\s*[a-zA-Z0-9_]+\s*=\s*\[.*?\]\s*$', '', txt, flags=re.MULTILINE | re.DOTALL)

    # Fix duplicate/wrong DLL attribution for CreateServiceA
    txt = re.sub(r'\s*pe\.imports\("KERNEL32\.DLL",\s*"CreateServiceA"\)\s*and\s*', '\n        ', txt, flags=re.IGNORECASE)

    if is_packed:
        txt = re.sub(
            r"math\.entropy\(0,\s*filesize\)\s*>=\s*\d+(?:\.\d+)?",
            "math.entropy(0, filesize) >= 5.0",
            txt
        )
    else:
        txt = re.sub(r"\s*math\.entropy\([^)]+\)\s*>=\s*\d+(?:\.\d+)?\s*and\s*", "\n        ", txt)
        txt = re.sub(r"\s*and\s*math\.entropy\([^)]+\)\s*>=\s*\d+(?:\.\d+)?", "", txt)

    # Make DLL/API matching case-insensitive in YARA PE module
    txt = re.sub(r'pe\.imports\("([^"]+)",\s*"([^"]+)"\)', r'pe.imports(/\1/i, /\2/i)', txt)

    # Adaptive string match threshold
    string_defs = len(re.findall(r"^\s*\$s\d+\s*=", txt, flags=re.MULTILINE))
    if is_packed:
        txt = re.sub(r"\b[2-9]\s+of\s+\(\$s\*\)", "1 of ($s*)", txt)
    elif string_defs >= 5:
        txt = re.sub(r"\b[1-2]\s+of\s+\(\$s\*\)", "3 of ($s*)", txt)

    return txt.strip()


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
        client = OpenAI(api_key=api_key, base_url="[https://api.groq.com/openai/v1](https://api.groq.com/openai/v1)")

    clean_profile = {
        "malware_type": str(profile.get("malware_type", "Malware")),
        "risk_level": str(profile.get("risk_level", "High"))
    }

    top_imports = {
        dll: funcs[:6]
        for dll, funcs in list(pe_data.get("imports_dll", {}).items())[:4]
    }
    max_entropy = max([s.get("Entropy", 0.0) for s in pe_data.get("sections", [])] or [0.0])
    is_packed = bool(pe_data.get("possible_packing", False))

    clean_strings = [
        s[:60] for s in pe_data.get("interesting_strings", [])
        if "DOS mode" not in s and not s.lower().endswith(".dll")
    ][:15]

    context = {
        "threat_profile": clean_profile,
        "possible_packing": is_packed,
        "overall_entropy_threshold": round(max(5.5, max_entropy - 0.6), 2),
        "imports_dll": top_imports,
        "interesting_strings": clean_strings,
        "sections": [s["Section"] for s in pe_data.get("sections", [])]
    }

    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": YARA_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(context)}
        ],
        "temperature": 0.1,
        "max_tokens": 600,
        "response_format": {"type": "json_object"}
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
            "yara_rule": sanitize_and_format_yara(raw_content, is_packed=is_packed),
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
    raw_yara = data.get("yara_rule") or data.get("regla_yara") or data.get("rule") or ""
    if not raw_yara.strip():
        raw_yara = raw_content
    rule_str = sanitize_and_format_yara(raw_yara, is_packed=is_packed)

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

    if not rule_str.strip() or "rule " not in rule_str:
        res["syntax_error"] = "Model returned empty or invalid YARA rule block."
        return res

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