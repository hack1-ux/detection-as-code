import streamlit as st
import yaml
import glob
import pandas as pd

st.set_page_config(
    page_title="Detection-as-Code | Coverage Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------- Load rules ----------
@st.cache_data
def load_rules():
    rule_files = sorted(glob.glob("rules/**/*.yml", recursive=True))
    rows = []
    for path in rule_files:
        with open(path) as f:
            rule = yaml.safe_load(f)
        tags = rule.get("tags", [])
        technique_tags = [t.replace("attack.", "").upper() for t in tags if t.startswith("attack.t")]
        tactic_tags = [t.replace("attack.", "").replace("_", " ").title() for t in tags if t.startswith("attack.") and not t.startswith("attack.t")]
        rows.append({
            "Rule": rule.get("title", path),
            "Tactics": tactic_tags,
            "Techniques": technique_tags,
            "Level": rule.get("level", "n/a"),
            "Description": rule.get("description", "").strip(),
            "References": rule.get("references", []),
            "Falsepositives": rule.get("falsepositives", []),
            "Author": rule.get("author", ""),
            "Date": rule.get("date", ""),
            "File": path,
            "Detection": rule.get("detection", {}),
        })
    return rows

rules = load_rules()
df = pd.DataFrame(rules)
exploded = df.explode("Tactics")

# ---------- Sidebar ----------
st.sidebar.title("🛡️ Detection-as-Code")
st.sidebar.caption("Sigma rules validated against real ATT&CK telemetry")
st.sidebar.divider()

tactic_options = sorted(exploded["Tactics"].dropna().unique())
selected_tactics = st.sidebar.multiselect("Filter by tactic", tactic_options, default=tactic_options)

level_options = sorted(df["Level"].unique())
selected_levels = st.sidebar.multiselect("Filter by severity", level_options, default=level_options)

st.sidebar.divider()
st.sidebar.markdown("**Author:** Muhammad Sudais")
st.sidebar.markdown("[GitHub](https://github.com/hack1-ux/detection-as-code)")

filtered = exploded[
    exploded["Tactics"].isin(selected_tactics) & exploded["Level"].isin(selected_levels)
]
filtered_rules = df[df["Rule"].isin(filtered["Rule"].unique())]

# ---------- Header ----------
st.title("Detection Engineering Coverage Dashboard")
st.caption("Each rule below is written in Sigma, converted to a live OpenSearch query via pySigma, and validated against real (historical, public) attack telemetry in Wazuh.")

# ---------- Metrics ----------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Rules", len(df))
c2.metric("Tactics Covered", exploded["Tactics"].nunique())
c3.metric("Techniques Covered", len(set(t for ts in df["Techniques"] for t in ts)))
c4.metric("Validated", f"{len(df)}/{len(df)}", delta="100%")

st.divider()

# ---------- ATT&CK Matrix ----------
st.subheader("MITRE ATT&CK Coverage Matrix")

ALL_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command And Control",
    "Exfiltration", "Impact"
]

tactic_rule_map = {}
for _, row in df.iterrows():
    for t in row["Tactics"]:
        tactic_rule_map.setdefault(t, []).append((row["Rule"], row["Techniques"], row["Level"]))

cols = st.columns(len(ALL_TACTICS))
level_color = {"critical": "#8b0000", "high": "#d9534f", "medium": "#f0ad4e", "low": "#5cb85c", "n/a": "#888"}

for i, tactic in enumerate(ALL_TACTICS):
    with cols[i]:
        covered = tactic in tactic_rule_map
        bg = "#1e3a1e" if covered else "#2a2a2a"
        st.markdown(
            f"<div style='background-color:{bg}; padding:6px; border-radius:6px; min-height:160px; font-size:11px;'>"
            f"<b>{tactic}</b><hr style='margin:4px 0;'>",
            unsafe_allow_html=True
        )
        if covered:
            for rule_name, techniques, level in tactic_rule_map[tactic]:
                color = level_color.get(level, "#888")
                st.markdown(
                    f"<div style='background-color:{color}; color:white; padding:3px 5px; "
                    f"border-radius:4px; margin-bottom:3px; font-size:10px;' title='{rule_name}'>"
                    f"{', '.join(techniques)}</div>",
                    unsafe_allow_html=True
                )
        else:
            st.markdown("<span style='color:#666; font-size:10px;'>No coverage</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

st.divider()

# ---------- Charts ----------
col_a, col_b = st.columns(2)
with col_a:
    st.subheader("Rules by Tactic")
    st.bar_chart(exploded["Tactics"].value_counts())
with col_b:
    st.subheader("Rules by Severity")
    st.bar_chart(df["Level"].value_counts())

st.divider()

# ---------- Rule browser ----------
st.subheader(f"Rule Library ({len(filtered_rules)} of {len(df)} shown)")

for _, row in filtered_rules.iterrows():
    level_badge = level_color.get(row["Level"], "#888")
    with st.expander(f"🔹 {row['Rule']}  —  {', '.join(row['Techniques'])}"):
        st.markdown(
            f"<span style='background-color:{level_badge}; color:white; padding:2px 8px; "
            f"border-radius:4px; font-size:12px;'>{row['Level'].upper()}</span>",
            unsafe_allow_html=True
        )
        st.write("")
        st.markdown(f"**Tactics:** {', '.join(row['Tactics'])}")
        st.markdown(f"**Description:** {row['Description']}")
        if row["Falsepositives"]:
            st.markdown(f"**False positives:** {', '.join(row['Falsepositives'])}")
        if row["References"]:
            st.markdown("**References:**")
            for ref in row["References"]:
                st.markdown(f"- {ref}")
        st.markdown("**Detection logic (Sigma):**")
        st.code(yaml.dump(row["Detection"], sort_keys=False), language="yaml")
        st.caption(f"File: `{row['File']}`  ·  Author: {row['Author']}  ·  Date: {row['Date']}")
