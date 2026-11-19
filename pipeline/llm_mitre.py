import json
import time
from openai import OpenAI


def generate_mitre_profile(provider: str, api_key: str, model: str, pe_data: dict) -> dict:
    t0 = time.time()

    if provider == "Local (Ollama)":
        client = OpenAI(api_key="ollama", base_url="http://localhost:11434/v1")
    else:
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

    compact_imports = {}
    for dll, funcs in pe_data["imports_dll"].items():
        clean = [f for f in funcs if not f.startswith("_")][:20]
        if clean:
            compact_imports[dll] = clean

    pe_summary = {
        "file": pe_data["file_name"],
        "compile_time": pe_data["compile_time"],
        "possible_packing": pe_data["possible_packing"],
        "packing_reasons": pe_data["packing_reasons"],
        "embedded_pe_resource": pe_data["embedded_pe"],
        "sections": pe_data["sections"],
        "imports_by_dll": compact_imports,
        "exports": pe_data["exports"][:15],
        "interesting_strings": pe_data["interesting_strings"][:30]
    }

    system_prompt = """You are a senior malware analyst. Analyze these static PE artifacts and respond EXCLUSIVELY with valid JSON:
{
  "malware_type": "Downloader / Dropper / Backdoor / Packed Binary",
  "risk_level": "High / Medium / Low",
  "diagnosis": "3-4 line technical summary of what the binary does.",
  "host_network_iocs": ["registry keys, file paths, mutexes, domains, or IPs"],
  "mitre_attack": [
    {"Tactic": "Persistence", "Tactic ID": "TA0003", "Technique": "Windows Service", "Technique ID": "T1543.003", "Evidence": "CreateServiceA"}
  ]
}"""

    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(pe_summary)}
        ],
        "temperature": 0.1,
        "max_tokens": 700
    }
    if provider == "Local (Ollama)":
        kwargs["extra_body"] = {"keep_alive": -1}
    else:
        kwargs["response_format"] = {"type": "json_object"}

    resp = client.chat.completions.create(**kwargs)
    raw = resp.choices[0].message.content
    start, end = raw.find("{"), raw.rfind("}")
    out = json.loads(raw[start:end + 1]) if start != -1 and end != -1 else json.loads(raw)
    out["elapsed_time"] = round(time.time() - t0, 2)
    return out