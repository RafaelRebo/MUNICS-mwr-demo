import os
import re
import json
import time
import yara
from openai import OpenAI

def limpiar_y_formatear_yara(regla_raw: str) -> str:
    txt = regla_raw.replace('\\n', '\n').replace('\\t', '    ').replace('\\"', '"').strip()
    
    if txt.count("\n") < 4:
        txt = re.sub(r'\s*\{\s*', ' {\n    ', txt, count=1)
        txt = re.sub(r'\s*(meta|strings|condition)\s*:\s*', r'\n\n    \1:\n        ', txt)
        txt = re.sub(r'\s+(\$[a-zA-Z0-9_]+\s*=)', r'\n        \1', txt)
        txt = re.sub(r'"\s+([a-zA-Z0-9_]+\s*=)', r'"\n        \1', txt)
        txt = re.sub(r'\s*\}\s*$', '\n}', txt)

    def _escapar_barras_en_string(match):
        contenido = match.group(1)
        contenido_limpio = contenido.replace('\\\\', '\\').replace('\\', '\\\\')
        return f'"{contenido_limpio}"'

    txt = re.sub(r'"([^"]*)"', _escapar_barras_en_string, txt)
    txt = re.sub(r';\s*$', '', txt, flags=re.MULTILINE)
    return txt

def generar_y_validar_yara(api_key: str, modelo: str, perfil: dict, datos_pe: dict, bytes_exe: bytes, dir_legitimos: str, dir_samples: str) -> dict:
    t0 = time.time()
    client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

    prompt = """Eres un ingeniero de detección especialista en YARA.
    Genera una regla YARA precisa basada en el perfil de amenaza y los indicadores encontrados.
    Responde ÚNICAMENTE con un objeto JSON válido (sin texto extra fuera de las llaves):
    {
      "nombre_regla": "Nombre_Regla_Sin_Espacios",
      "explicacion": "Por qué se eligieron estos indicadores para evitar falsos positivos.",
      "regla_yara": "rule Nombre_Regla_Sin_Espacios { meta: ... strings: ... condition: uint16(0) == 0x5A4D and ... }"
    }
    Reglas:
    1. Empieza siempre la condition con: uint16(0) == 0x5A4D
    2. Usa indicadores únicos del malware (dominios, mutex, claves de registro, nombres de archivo o secciones UPX0/UPX1 si está empaquetado). Evita nombres genéricos de Windows."""

    contexto = {
        "perfil": perfil,
        "strings": datos_pe["strings_interesantes"][:35],
        "secciones": [s["Sección"] for s in datos_pe["secciones"]]
    }

    # SIN response_format para que Groq no lance Error 400 si un modelo pequeño falla
    resp = client.chat.completions.create(
        model=modelo,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(contexto, indent=2)}
        ],
        temperature=0.1
    )
    
    raw_content = resp.choices[0].message.content
    try:
        match_json = re.search(r'\{.*\}', raw_content, re.DOTALL)
        data = json.loads(match_json.group(0))
    except Exception:
        return {
            "nombre_regla": "Error_Formato_LLM",
            "explicacion": "El modelo ligero no respetó la estructura JSON al incluir código YARA.",
            "regla_yara": raw_content,
            "compila": False,
            "error_sintaxis": "Fallo de estructuración JSON en salida del modelo",
            "match_objetivo": False,
            "offsets": [],
            "fps": 0,
            "tabla_legitimos": [],
            "tabla_samples": [],
            "tiempo": round(time.time() - t0, 2)
        }

    regla_str = limpiar_y_formatear_yara(data.get("regla_yara", ""))

    res = {
        "nombre_regla": data.get("nombre_regla", "Regla_YARA"),
        "explicacion": data.get("explicacion", ""),
        "regla_yara": regla_str,
        "compila": False,
        "error_sintaxis": "",
        "match_objetivo": False,
        "offsets": [],
        "fps": 0,
        "tabla_legitimos": [],
        "tabla_samples": [],
        "tiempo": round(time.time() - t0, 2)
    }

    try:
        regla = yara.compile(source=regla_str)
        res["compila"] = True
    except yara.SyntaxError as e:
        res["error_sintaxis"] = str(e)
        return res

    # 1. Escaneo muestra objetivo y extracción de offsets exactos
    hits = regla.match(data=bytes_exe)
    if hits:
        res["match_objetivo"] = True
        for m in hits:
            for s in m.strings:
                for inst in s.instances:
                    res["offsets"].append({
                        "Variable YARA": s.identifier,
                        "Offset en Binario": hex(inst.offset),
                        "String Detectada": inst.matched_data.decode('utf-8', errors='replace')[:70]
                    })

    # 2. Validación contra corpus legítimo (Falsos Positivos)
    if os.path.exists(dir_legitimos):
        for f in sorted(os.listdir(dir_legitimos)):
            ruta = os.path.join(dir_legitimos, f)
            if os.path.isfile(ruta):
                alerta = bool(regla.match(ruta))
                if alerta:
                    res["fps"] += 1
                res["tabla_legitimos"].append({
                    "Archivo Legítimo": f,
                    "Resultado": "⚠️ FALSO POSITIVO" if alerta else "✅ Limpio"
                })

    # 3. Barrido sobre el resto de muestras de laboratorio
    if os.path.exists(dir_samples):
        for f in sorted(os.listdir(dir_samples)):
            ruta = os.path.join(dir_samples, f)
            if os.path.isfile(ruta):
                alerta = bool(regla.match(ruta))
                res["tabla_samples"].append({
                    "Muestra": f,
                    "Resultado": "✅ DETECTADO" if alerta else "➖ Sin coincidencia"
                })

    return res