"""
dashboard.py

A simple Streamlit dashboard summarizing prioritized security findings
(output of prioritize.py). Run locally with:

    streamlit run dashboard.py

Expects findings/prioritized_report.json to exist (run fetch_findings.py
and prioritize.py first).
"""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="DevSecOps Findings Dashboard", layout="wide")

REPORT_PATH = Path("findings/prioritized_report.json")

SEVERITY_COLORS = {
    "critical": "#d62728",
    "high": "#ff7f0e",
    "medium": "#f2c94c",
    "low": "#2ca02c",
    "unknown": "#7f7f7f",
}


@st.cache_data
def load_report(path: Path) -> pd.DataFrame:
    data = json.loads(path.read_text())
    rows = []
    for g in data:
        rows.append({
            "Severity": g["severity"].capitalize(),
            "Rule ID": g["rule_id"],
            "Description": g["description"],
            "Tool": g["tool"],
            "Occurrences": g["occurrence_count"],
            "Files": ", ".join(sorted({loc["file"] for loc in g["locations"]})),
        })
    return pd.DataFrame(rows)


def main():
    st.title("🔒 DevSecOps Findings Dashboard")
    st.caption("Summary of prioritized SAST/SCA/DAST findings from the security pipeline")

    if not REPORT_PATH.exists():
        st.error(
            f"Report not found at `{REPORT_PATH}`. "
            "Run `fetch_findings.py` then `prioritize.py` first to generate it."
        )
        st.stop()

    df = load_report(REPORT_PATH)

    # --- Top-line metrics ---
    total_findings = int(df["Occurrences"].sum())
    total_rule_types = len(df)
    critical_count = int(df.loc[df["Severity"] == "Critical", "Occurrences"].sum())
    high_count = int(df.loc[df["Severity"] == "High", "Occurrences"].sum())

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total findings", total_findings)
    col2.metric("Distinct issue types", total_rule_types)
    col3.metric("Critical findings", critical_count)
    col4.metric("High findings", high_count)

    st.divider()

    # --- Severity breakdown chart ---
    left, right = st.columns([1, 2])

    with left:
        st.subheader("By severity")
        severity_counts = (
            df.groupby("Severity")["Occurrences"].sum().reindex(
                ["Critical", "High", "Medium", "Low"], fill_value=0
            )
        )
        st.bar_chart(severity_counts)

    with right:
        st.subheader("Top issue types by occurrence")
        top = df.sort_values("Occurrences", ascending=False).head(10)
        st.dataframe(
            top[["Severity", "Rule ID", "Description", "Occurrences"]],
            hide_index=True,
            use_container_width=True,
        )

    st.divider()

    # --- Critical findings, called out explicitly ---
    st.subheader("🔴 Critical findings — needs attention")
    critical_df = df[df["Severity"] == "Critical"].sort_values("Occurrences", ascending=False)
    if critical_df.empty:
        st.success("No critical findings.")
    else:
        st.dataframe(critical_df, hide_index=True, use_container_width=True)

    st.divider()

    # --- Full filterable table ---
    st.subheader("All findings")
    severity_filter = st.multiselect(
        "Filter by severity",
        options=sorted(df["Severity"].unique(), key=lambda s: s not in ["Critical"]),
        default=list(df["Severity"].unique()),
    )
    filtered = df[df["Severity"].isin(severity_filter)].sort_values(
        by="Severity", key=lambda s: s.map({"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4})
    )
    st.dataframe(filtered, hide_index=True, use_container_width=True)


if __name__ == "__main__":
    main()