import json
import time
from openai import OpenAI

def generar_perfil_mitre(api_key: str, modelo: str, datos_pe: dict) -> dict:
    t0 = time.time()
    client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

    resumen_pe = {
        "archivo": datos_pe["nombre"],
        "compile_time": datos_pe["compile_time"],
        "posible_packing": datos_pe["posible_packing"],
        "motivos_packing": datos_pe["motivos_packing"],
        "recurso_pe_incrustado": datos_pe["recurso_pe_oculto"],
        "secciones": datos_pe["secciones"],
        "imports_por_dll": datos_pe["imports_dll"],
        "exports": datos_pe["exports"],
        "strings_relevantes": datos_pe["strings_interesantes"][:40]
    }

    prompt = """Eres un analista de malware. Analiza estos artefactos extraídos mediante análisis estático básico (PEview, Imports/Exports y Strings).
    Responde EXCLUSIVAMENTE en JSON válido:
    {
      "tipo_malware": "Ej: Downloader / Dropper / Backdoor / Packed Binary",
      "riesgo": "Alto / Medio / Bajo",
      "diagnostico": "Explicación clara en 3-4 líneas de qué hace el binario basándote en sus imports, secciones y strings.",
      "indicadores_host_red": ["Lista de IoCs encontrados: rutas de registro, nombres de archivo, mutex, dominios o IPs"],
      "mitre_attack": [
        {"Táctica": "Ej: Persistence", "ID": "T1547.001", "Técnica": "Registry Run Keys", "Evidencia": "String o API exacta"}
      ]
    }"""

    resp = client.chat.completions.create(
        model=modelo,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(resumen_pe, indent=2)}
        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )
    out = json.loads(resp.choices[0].message.content)
    out["tiempo"] = round(time.time() - t0, 2)
    return out