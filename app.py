import os
import streamlit as st
import pandas as pd
from openai import OpenAI

from pipeline.static_pe import analizar_pe
from pipeline.llm_mitre import generar_perfil_mitre
from pipeline.yara_validator import generar_y_validar_yara

st.set_page_config(page_title="AI Malware Triage & YARA", page_icon="🛡️", layout="wide")
st.title("🛡️ Automated Malware Triage & YARA Pipeline")
st.caption("Extracción Estática (IAT, Entropías de Sección y Strings) ➔ Threat Profiling & MITRE ATT&CK ➔ Regla YARA & Validación FP")

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Configuración")
    api_key = st.text_input("Groq API Key (gsk_...):", type="password")
    
    modelos = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "llama-3.1-8b-instant"]
    if api_key:
        try:
            c = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
            activos = [m.id for m in c.models.list().data if not any(x in m.id.lower() for x in ["whisper", "guard", "tts", "orpheus"])]
            if activos:
                modelos = sorted(activos, key=lambda x: (0 if "120b" in x or "70b" in x or "qwen" in x else 1, x))
        except Exception:
            pass
    modelo = st.selectbox("Modelo LLM:", modelos)

    st.divider()
    dir_legitimos = st.text_input("Carpeta legítimos:", value="legitimate_files")
    dir_samples = st.text_input("Carpeta muestras:", value="samples")
    if os.path.exists(dir_legitimos):
        st.success(f"✅ {len(os.listdir(dir_legitimos))} archivos legítimos listos")

# --- SUBIDA DE ARCHIVO ---
archivo = st.file_uploader("Sube un ejecutable Windows (.exe)", type=["exe"])

if archivo:
    if st.session_state.get("archivo_actual") != archivo.name:
        st.session_state["archivo_actual"] = archivo.name
        st.session_state.pop("perfil", None)
        st.session_state.pop("yara", None)

    bytes_exe = archivo.read()
    pe_data = analizar_pe(bytes_exe, archivo.name)

    # ================= FASE 1: ANÁLISIS ESTÁTICO =================
    st.header("1️⃣ Fase 1: Análisis Estático (IAT, Entropías y Strings)")
    
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Time Date Stamp", pe_data["compile_time"].split(" ")[0])
    c2.metric("Imports (IAT)", f"{pe_data['total_imports']} funcs")
    c3.metric("Packing / Entropía", "⚠️ POSIBLE PACKER" if pe_data["posible_packing"] else "✅ Estándar")
    c4.metric("Sección .rsrc", "🚨 EXE incrustado" if pe_data["recurso_pe_oculto"] else ("Presente" if pe_data["tiene_rsrc"] else "No"))

    if pe_data["motivos_packing"]:
        st.warning("**Alertas de empaquetado / entropía:** " + " | ".join(pe_data["motivos_packing"]))

    with st.expander("🔍 Ver detalles técnicos (Hashes, Secciones & Entropía, IAT/EAT y Strings)", expanded=True):
        st.code(f"MD5: {pe_data['md5']}  |  SHA256: {pe_data['sha256']}\nCompilation Time Stamp: {pe_data['compile_time']}", language="text")
        
        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("Secciones PE y Entropía de Shannon")
            df_sec = pd.DataFrame(pe_data["secciones"])
            st.dataframe(df_sec, use_container_width=True, hide_index=True)
            st.bar_chart(df_sec.set_index("Sección")["Entropía"], height=160)
            
            st.subheader("Imports por DLL (IAT) y Exports (EAT)")
            if pe_data["imports_dll"]:
                st.json(pe_data["imports_dll"], expanded=True)
            else:
                st.info("Sin tabla de importaciones visible.")
            if pe_data["exports"]:
                st.write("**Exports:**", ", ".join(pe_data["exports"]))

        with col_b:
            st.subheader("Strings Relevantes (-n 6)")
            st.text_area("Indicadores extraídos:", "\n".join(pe_data["strings_interesantes"]), height=260)
            st.subheader("Otras Strings")
            st.text_area("Cadenas adicionales:", "\n".join(pe_data["strings_otras"]), height=160)

    st.divider()

    # ================= FASE 2: MITRE ATT&CK =================
    st.header("2️⃣ Fase 2: Threat Profiling y Mapeo MITRE ATT&CK")
    if st.button("🧠 Ejecutar Fase 2: Clasificar y Mapear MITRE", type="primary"):
        if not api_key:
            st.warning("⚠️ Introduce tu API Key en la barra lateral.")
            st.stop()
        with st.spinner("Analizando artefactos con el LLM..."):
            st.session_state["perfil"] = generar_perfil_mitre(api_key, modelo, pe_data)

    if "perfil" in st.session_state:
        p = st.session_state["perfil"]
        m1, m2, m3 = st.columns(3)
        m1.metric("Clasificación", p.get("tipo_malware", "N/A"))
        m2.metric("Riesgo", p.get("riesgo", "N/A"))
        m3.metric("Tiempo LLM", f"{p.get('tiempo', 0)} s")
        st.info(p.get("diagnostico", ""))
        if p.get("mitre_attack"):
            st.dataframe(pd.DataFrame(p["mitre_attack"]), use_container_width=True, hide_index=True)

        st.divider()

        # ================= FASE 3: YARA Y VALIDACIÓN =================
        st.header("3️⃣ Fase 3: Síntesis de Regla YARA y Validación")
        if st.button("🎯 Ejecutar Fase 3: Generar Regla YARA y Validar", type="primary"):
            with st.spinner("Generando regla YARA y escaneando archivos..."):
                st.session_state["yara"] = generar_y_validar_yara(
                    api_key, modelo, p, pe_data, bytes_exe, dir_legitimos, dir_samples
                )

    if "yara" in st.session_state:
        y = st.session_state["yara"]
        cy1, cy2 = st.columns([1.4, 1])
        with cy1:
            st.subheader("Regla YARA Generada")
            st.code(y["regla_yara"], language="yara")
            st.download_button("💾 Descargar .yar", y["regla_yara"], file_name=f"{y['nombre_regla']}.yar")
        with cy2:
            st.subheader("Criterio de Detección")
            st.write(y["explicacion"])
            st.metric("Tiempo Total Fase 3", f"{y['tiempo']} s")

        if y["compila"]:
            v1, v2, v3 = st.columns(3)
            v1.metric("1. Sintaxis YARA", "VÁLIDA ✅")
            v2.metric("2. Muestra Objetivo", "DETECTADA ✅" if y["match_objetivo"] else "NO DETECTADA ❌")
            v3.metric("3. Falsos Positivos", f"{y['fps']} / {len(y['tabla_legitimos'])} {'✅' if y['fps'] == 0 else '⚠️'}")

            t1, t2, t3 = st.tabs(["📍 Offsets en el Binario", "🛡️ Test Corpus Legítimo", "🧪 Test Otras Muestras"])
            with t1:
                st.dataframe(pd.DataFrame(y["offsets"]), use_container_width=True, hide_index=True)
            with t2:
                st.dataframe(pd.DataFrame(y["tabla_legitimos"]), use_container_width=True, hide_index=True)
            with t3:
                st.dataframe(pd.DataFrame(y["tabla_samples"]), use_container_width=True, hide_index=True)
        else:
            st.error(f"❌ Error de sintaxis YARA: {y['error_sintaxis']}")