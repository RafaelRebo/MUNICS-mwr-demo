import os
import streamlit as st
import pandas as pd
from openai import OpenAI

from pipeline.static_pe import analyze_pe
from pipeline.llm_mitre import generate_mitre_profile
from pipeline.yara_validator import generate_and_validate_yara

st.set_page_config(page_title="AI Malware Triage & YARA Pipeline", layout="wide")

# --- CUSTOM CSS FOR CLEAN TECHNICAL BADGES & UI ---
st.markdown("""
<style>
.badge {
    display: inline-block;
    padding: 3px 10px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    border-radius: 4px;
    text-transform: uppercase;
    margin-bottom: 6px;
}
.badge-ok { background-color: #0f3d2e; color: #34d399; border: 1px solid #059669; }
.badge-warn { background-color: #422006; color: #fbbf24; border: 1px solid #d97706; }
.badge-err { background-color: #450a0a; color: #f87171; border: 1px solid #dc2626; }
.badge-info { background-color: #172554; color: #60a5fa; border: 1px solid #2563eb; }
.phase-header {
    border-left: 4px solid #3b82f6;
    padding-left: 12px;
    margin-top: 10px;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)


def badge(text: str, kind: str = "info") -> str:
    return f'<span class="badge badge-{kind}">{text}</span>'


st.title("Automated Malware Triage & YARA Synthesis Pipeline")
st.caption("Static PE Feature Extraction (IAT, Section Entropy, Strings)  |  MITRE ATT&CK Threat Profiling  |  Zero-FP YARA v4 Synthesis")

# --- SIDEBAR ---
with st.sidebar:
    st.header("Inference Configuration")
    provider = st.radio(
        "Execution Provider:",
        ["Local (Ollama)", "Cloud (Groq API)"],
        index=0
    )

    api_key = ""
    if provider == "Local (Ollama)":
        local_models = ["yara-expert-3b", "qwen2.5-coder:3b"]
        try:
            c = OpenAI(api_key="ollama", base_url="http://localhost:11434/v1")
            installed = [m.id for m in c.models.list().data]
            if installed:
                # Prioritize yara-expert-3b at the top of the dropdown
                local_models = sorted(installed, key=lambda x: (0 if "yara-expert" in x else 1, x))
            st.markdown(badge("OLLAMA ONLINE (LOCAL GPU)", "ok"), unsafe_allow_html=True)
        except Exception:
            st.markdown(badge("OLLAMA SERVER OFFLINE", "err"), unsafe_allow_html=True)
        model = st.selectbox("Local Model:", local_models)
    else:
        api_key = st.text_input("Groq API Key (gsk_...):", type="password")
        cloud_models = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "llama-3.1-8b-instant"]
        if api_key:
            try:
                c = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
                active = [
                    m.id for m in c.models.list().data
                    if not any(x in m.id.lower() for x in ["whisper", "guard", "tts", "orpheus"])
                ]
                if active:
                    cloud_models = sorted(active, key=lambda x: (0 if "120b" in x or "70b" in x or "qwen" in x else 1, x))
            except Exception:
                pass
        model = st.selectbox("Cloud Model:", cloud_models)

    st.divider()
    st.subheader("Validation Corpus")
    legit_dir = st.text_input("Benign Binaries Directory:", value="legitimate_files")
    samples_dir = st.text_input("Malware Samples Directory:", value="samples")
    if os.path.exists(legit_dir):
        count = len([f for f in os.listdir(legit_dir) if os.path.isfile(os.path.join(legit_dir, f))])
        st.markdown(badge(f"{count} BENIGN BINARIES LOADED", "ok"), unsafe_allow_html=True)
    else:
        st.markdown(badge("BENIGN DIRECTORY NOT FOUND", "warn"), unsafe_allow_html=True)

# --- FILE UPLOAD ---
uploaded_file = st.file_uploader("Upload Windows PE Executable (.exe / .dll)", type=["exe", "dll"])

if uploaded_file:
    if st.session_state.get("current_file") != uploaded_file.name:
        st.session_state["current_file"] = uploaded_file.name
        st.session_state.pop("profile", None)
        st.session_state.pop("yara", None)
        st.session_state.pop("benchmark", None)

    exe_bytes = uploaded_file.read()
    pe_data = analyze_pe(exe_bytes, uploaded_file.name)

    # ================= PHASE 1: STATIC ANALYSIS =================
    st.markdown('<div class="phase-header"><h3>Phase 1: Static PE Analysis (IAT, Section Entropy & Strings)</h3></div>', unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Compile Timestamp", pe_data["compile_time"].split(" ")[0])
    c2.metric("Imported Functions (IAT)", f"{pe_data['total_imports']} funcs")
    c3.metric("Packing / Entropy Status", "ANOMALOUS" if pe_data["possible_packing"] else "STANDARD")
    c4.metric("Resource Section (.rsrc)", "EMBEDDED PE" if pe_data["embedded_pe"] else ("PRESENT" if pe_data["has_rsrc"] else "ABSENT"))

    if pe_data["packing_reasons"]:
        st.warning("Packing / Entropy Anomalies: " + " | ".join(pe_data["packing_reasons"]))

    with st.expander("Inspect Technical Artifacts (Hashes, Sections, IAT/EAT & Strings)", expanded=True):
        st.code(
            f"MD5:    {pe_data['md5']}\n"
            f"SHA256: {pe_data['sha256']}\n"
            f"TimeDateStamp: {pe_data['compile_time']}",
            language="text"
        )

        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("PE Sections & Shannon Entropy")
            df_sec = pd.DataFrame(pe_data["sections"])
            st.dataframe(df_sec, use_container_width=True, hide_index=True)
            st.bar_chart(df_sec.set_index("Section")["Entropy"], height=160)

            st.subheader("Import Address Table (IAT) & Exports (EAT)")
            if pe_data["imports_dll"]:
                st.json(pe_data["imports_dll"], expanded=True)
            else:
                st.info("No standard import table visible.")
            if pe_data["exports"]:
                st.write("**Exported Symbols:**", ", ".join(pe_data["exports"]))

        with col_b:
            st.subheader("Filtered High-Signal Strings (-n 6)")
            st.text_area("Extracted Indicators:", "\n".join(pe_data["interesting_strings"]), height=260)
            st.subheader("Additional Strings")
            st.text_area("Secondary Strings:", "\n".join(pe_data["other_strings"]), height=160)

    st.divider()

    # ================= PHASE 2: MITRE ATT&CK =================
    st.markdown('<div class="phase-header"><h3>Phase 2: Threat Profiling & MITRE ATT&CK Mapping</h3></div>', unsafe_allow_html=True)

    if st.button("Run Phase 2: Classify & Map MITRE ATT&CK", type="primary"):
        if provider == "Cloud (Groq API)" and not api_key:
            st.warning("Please enter your Groq API Key in the sidebar.")
            st.stop()
        with st.spinner(f"Analyzing static artifacts with {model}..."):
            st.session_state["profile"] = generate_mitre_profile(provider, api_key, model, pe_data)

    if "profile" in st.session_state:
        p = st.session_state["profile"]
        m1, m2, m3 = st.columns(3)
        m1.metric("Threat Classification", p.get("malware_type", "N/A"))
        m2.metric("Risk Level", p.get("risk_level", "N/A"))
        m3.metric("Inference Latency", f"{p.get('elapsed_time', 0)} s")
        st.info(p.get("diagnosis", ""))
        if p.get("mitre_attack"):
            st.dataframe(pd.DataFrame(p["mitre_attack"]), use_container_width=True, hide_index=True)

        st.divider()

        # ================= PHASE 3: YARA SYNTHESIS & AUDIT =================
        st.markdown('<div class="phase-header"><h3>Phase 3: YARA v4 Rule Synthesis & Zero-FP Validation</h3></div>', unsafe_allow_html=True)

        btn_col1, btn_col2 = st.columns(2)
        with btn_col1:
            run_single = st.button(f"Generate & Validate YARA Rule ({model})", type="primary", use_container_width=True)
        with btn_col2:
            run_bench = st.button("Benchmark Local Models: Untrained Base (3B) vs. Fine-Tuned (3B)", use_container_width=True)

        if run_single:
            with st.spinner(f"Synthesizing YARA rule with {model} and auditing against benign corpus..."):
                st.session_state["yara"] = generate_and_validate_yara(
                    provider, api_key, model, p, pe_data, exe_bytes, legit_dir, samples_dir
                )

        if run_bench:
            with st.spinner("Running head-to-head local evaluation on RTX GPU (Base 3B vs. Fine-Tuned 3B)..."):
                res_base = generate_and_validate_yara(
                    "Local (Ollama)", "", "qwen2.5-coder:3b", p, pe_data, exe_bytes, legit_dir, samples_dir
                )
                res_ft = generate_and_validate_yara(
                    "Local (Ollama)", "", "yara-expert-3b", p, pe_data, exe_bytes, legit_dir, samples_dir
                )
                st.session_state["benchmark"] = (res_base, res_ft)

    if "yara" in st.session_state:
        y = st.session_state["yara"]
        cy1, cy2 = st.columns([1.4, 1])
        with cy1:
            st.subheader("Generated YARA v4 Rule")
            st.code(y["yara_rule"], language="yara")
            st.download_button("Download .yar File", y["yara_rule"], file_name=f"{y['rule_name']}.yar")
        with cy2:
            st.subheader("Detection Engineering Rationale")
            st.write(y["rationale"])
            st.metric("Total Phase 3 Latency", f"{y['elapsed_time']} s")

        if y["compiles"]:
            v1, v2, v3 = st.columns(3)
            with v1:
                st.markdown(badge("SYNTAX: VALID", "ok"), unsafe_allow_html=True)
                st.metric("1. YARA Compiler", "PASSED")
            with v2:
                st.markdown(badge("TARGET: MATCHED" if y["target_match"] else "TARGET: MISSED", "ok" if y["target_match"] else "err"), unsafe_allow_html=True)
                st.metric("2. Target Binary", "DETECTED" if y["target_match"] else "NOT DETECTED")
            with v3:
                fp_kind = "ok" if y["fps"] == 0 else "err"
                st.markdown(badge("ZERO FALSE POSITIVES" if y["fps"] == 0 else "FALSE POSITIVES DETECTED", fp_kind), unsafe_allow_html=True)
                st.metric("3. Clean Corpus FPs", f"{y['fps']} / {len(y['legit_table'])}")

            t1, t2, t3 = st.tabs(["Binary Byte Offsets", "Benign Corpus Audit", "Malware Lab Sweep"])
            with t1:
                st.dataframe(pd.DataFrame(y["offsets"]), use_container_width=True, hide_index=True)
            with t2:
                st.dataframe(pd.DataFrame(y["legit_table"]), use_container_width=True, hide_index=True)
            with t3:
                st.dataframe(pd.DataFrame(y["samples_table"]), use_container_width=True, hide_index=True)
        else:
            st.error(f"YARA Compilation Error: {y['syntax_error']}")

    # --- HEAD-TO-HEAD BENCHMARK VIEW ---
    if "benchmark" in st.session_state:
        st.divider()
        st.markdown('<div class="phase-header"><h3>Head-to-Head Local Benchmark: Untrained Base vs. QLoRA Fine-Tuned</h3></div>', unsafe_allow_html=True)
        res_base, res_ft = st.session_state["benchmark"]
        bcol1, bcol2 = st.columns(2)

        for col, title, res in [
            (bcol1, "Untrained Base (qwen2.5-coder:3b)", res_base),
            (bcol2, "Fine-Tuned Model (yara-expert-3b)", res_ft)
        ]:
            with col:
                st.subheader(title)
                if res["compiles"] and res["target_match"] and res["fps"] == 0:
                    st.markdown(badge("PRODUCTION READY (0 FP)", "ok"), unsafe_allow_html=True)
                elif not res["compiles"]:
                    st.markdown(badge("SYNTAX / JSON FAILURE", "err"), unsafe_allow_html=True)
                else:
                    st.markdown(badge(f"FAILED AUDIT ({res['fps']} FPs)", "warn"), unsafe_allow_html=True)

                bm1, bm2, bm3 = st.columns(3)
                bm1.metric("Compiles", "YES" if res["compiles"] else "NO")
                bm2.metric("Target Hit", "YES" if res["target_match"] else "NO")
                bm3.metric("False Positives", f"{res['fps']} ({res['elapsed_time']}s)")
                st.code(res["yara_rule"], language="yara")
                if not res["compiles"]:
                    st.error(res["syntax_error"])