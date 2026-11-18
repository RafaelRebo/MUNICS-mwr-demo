import pefile
import hashlib
import math
import re
from datetime import datetime, timezone

def calcular_entropia(datos: bytes) -> float:
    if not datos:
        return 0.0
    frecuencias = [0] * 256
    for byte in datos:
        frecuencias[byte] += 1
    entropia = 0.0
    longitud = len(datos)
    for f in frecuencias:
        if f > 0:
            p = f / longitud
            entropia -= p * math.log2(p)
    return round(entropia, 3)

def analizar_pe(bytes_archivo: bytes, nombre_archivo: str) -> dict:
    pe = pefile.PE(data=bytes_archivo)
    
    # 1. Hashes y Time Date Stamp (PEview -> IMAGE_FILE_HEADER)
    md5 = hashlib.md5(bytes_archivo).hexdigest()
    sha256 = hashlib.sha256(bytes_archivo).hexdigest()
    ts = pe.FILE_HEADER.TimeDateStamp
    compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # 2. Secciones PE: Entropía de Shannon + Raw vs Virtual Size
    secciones = []
    posible_packing = False
    motivos_packing = []
    tiene_rsrc = False

    for sec in pe.sections:
        nombre = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
        v_size = sec.Misc_VirtualSize
        r_size = sec.SizeOfRawData
        entropia = calcular_entropia(sec.get_data())
        
        if nombre == ".rsrc":
            tiene_rsrc = True

        es_anomala = False
        if entropia > 7.0:
            posible_packing = True
            es_anomala = True
            motivos_packing.append(f"{nombre or 'sección'}: Entropía alta ({entropia} > 7.0)")
        if "UPX" in nombre.upper() or nombre == "":
            posible_packing = True
            es_anomala = True
            motivos_packing.append(f"Nombre anómalo ('{nombre or 'sin nombre'}')")
        if r_size == 0 and v_size > 0:
            posible_packing = True
            es_anomala = True
            motivos_packing.append(f"{nombre}: Raw Size 0 vs Virtual {hex(v_size)}")

        secciones.append({
            "Sección": nombre if nombre else "(sin nombre)",
            "Raw Size": hex(r_size),
            "Virtual Size": hex(v_size),
            "Entropía": entropia,
            "Estado": "⚠️ Packed / Alta Entropía" if es_anomala else "✅ Normal"
        })

    # 3. Import Address Table (IAT) y Export Address Table (EAT)
    imports_dll = {}
    total_imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            funcs = [imp.name.decode('utf-8', errors='ignore') for imp in entry.imports if imp.name]
            if funcs:
                imports_dll[dll] = funcs
                total_imports += len(funcs)
        if total_imports <= 2:
            posible_packing = True
            motivos_packing.append(f"IAT mínima ({total_imports} imports)")

    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(f"{exp.name.decode('utf-8', errors='ignore')} (Ordinal {exp.ordinal})")

    # 4. Recurso PE incrustado en .rsrc (Lab01-04)
    recurso_pe_oculto = len(re.findall(rb"This program cannot be run in DOS mode", bytes_archivo)) > 1

    # 5. Strings embebidas (-n 6)
    raw_strings = re.findall(rb"[A-Za-z0-9_\-\.\/\\:=\?\s@]{6,}", bytes_archivo)
    claves = ["http", "www", ".com", ".exe", ".dll", "software\\", "microsoft", "currentversion", "run", "service", "winvmx", "upx", "cmd", "system32", "privilege"]
    
    strings_interesantes, strings_otras = [], []
    for s in raw_strings:
        txt = s.decode('utf-8', errors='ignore').strip()
        if 6 <= len(txt) <= 120:
            if any(k in txt.lower() for k in claves) and txt not in strings_interesantes:
                strings_interesantes.append(txt)
            elif txt not in strings_otras:
                strings_otras.append(txt)

    return {
        "nombre": nombre_archivo,
        "md5": md5,
        "sha256": sha256,
        "compile_time": compile_time,
        "posible_packing": posible_packing,
        "motivos_packing": list(set(motivos_packing)),
        "tiene_rsrc": tiene_rsrc,
        "recurso_pe_oculto": recurso_pe_oculto,
        "secciones": secciones,
        "total_imports": total_imports,
        "imports_dll": imports_dll,
        "exports": exports,
        "strings_interesantes": strings_interesantes[:50],
        "strings_otras": strings_otras[:30]
    }