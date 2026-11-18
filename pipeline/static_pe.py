import pefile
import hashlib
import math
import re
from datetime import datetime, timezone


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1
    entropy = 0.0
    length = len(data)
    for f in frequencies:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_pe(file_bytes: bytes, file_name: str) -> dict:
    pe = pefile.PE(data=file_bytes)

    # 1. Hashes & Time Date Stamp (IMAGE_FILE_HEADER)
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    ts = pe.FILE_HEADER.TimeDateStamp
    compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 2. PE Sections: Shannon Entropy & Raw vs Virtual Size
    sections = []
    possible_packing = False
    packing_reasons = []
    has_rsrc = False

    for sec in pe.sections:
        name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
        v_size = sec.Misc_VirtualSize
        r_size = sec.SizeOfRawData
        entropy = calculate_entropy(sec.get_data())

        if name == ".rsrc":
            has_rsrc = True

        is_anomalous = False
        if entropy > 7.0:
            possible_packing = True
            is_anomalous = True
            packing_reasons.append(f"{name or 'unnamed'}: High entropy ({entropy} > 7.0)")
        if "UPX" in name.upper() or name == "":
            possible_packing = True
            is_anomalous = True
            packing_reasons.append(f"Anomalous section name ('{name or 'unnamed'}')")
        if r_size == 0 and v_size > 0:
            possible_packing = True
            is_anomalous = True
            packing_reasons.append(f"{name}: Raw Size 0 vs Virtual {hex(v_size)}")

        sections.append({
            "Section": name if name else "(unnamed)",
            "Raw Size": hex(r_size),
            "Virtual Size": hex(v_size),
            "Entropy": entropy,
            "Status": "PACKED / HIGH ENTROPY" if is_anomalous else "NORMAL"
        })

    # 3. Import Address Table (IAT) & Export Address Table (EAT)
    imports_dll = {}
    total_imports = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="ignore")
            funcs = [imp.name.decode("utf-8", errors="ignore") for imp in entry.imports if imp.name]
            if funcs:
                imports_dll[dll] = funcs
                total_imports += len(funcs)
        if total_imports <= 2:
            possible_packing = True
            packing_reasons.append(f"Minimal IAT ({total_imports} imports)")

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(f"{exp.name.decode('utf-8', errors='ignore')} (Ordinal {exp.ordinal})")

    # 4. Embedded PE Resource inside .rsrc
    embedded_pe = len(re.findall(rb"This program cannot be run in DOS mode", file_bytes)) > 1

    # 5. Embedded Strings (-n 6)
    raw_strings = re.findall(rb"[A-Za-z0-9_\-\.\/\\:=\?\s@]{6,}", file_bytes)
    keywords = [
        "http", "www", ".com", ".exe", ".dll", "software\\", "microsoft",
        "currentversion", "run", "service", "winvmx", "upx", "cmd", "system32", "privilege"
    ]

    interesting_strings, other_strings = [], []
    for s in raw_strings:
        txt = s.decode("utf-8", errors="ignore").strip()
        if 6 <= len(txt) <= 120:
            if any(k in txt.lower() for k in keywords) and txt not in interesting_strings:
                interesting_strings.append(txt)
            elif txt not in other_strings:
                other_strings.append(txt)

    return {
        "file_name": file_name,
        "md5": md5,
        "sha256": sha256,
        "compile_time": compile_time,
        "possible_packing": possible_packing,
        "packing_reasons": list(set(packing_reasons)),
        "has_rsrc": has_rsrc,
        "embedded_pe": embedded_pe,
        "sections": sections,
        "total_imports": total_imports,
        "imports_dll": imports_dll,
        "exports": exports,
        "interesting_strings": interesting_strings[:50],
        "other_strings": other_strings[:30]
    }