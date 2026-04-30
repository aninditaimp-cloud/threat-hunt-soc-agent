import streamlit as st
import pandas as pd

# ── Agents ──────────────────────────────────────────

def hypothesis_agent():
    return "Check for brute force: many failed logins from same IP."

def analyst_agent(data):
    failed = data[data["status"] == "failed"]
    return failed.groupby("ip").size()

def count_failed_per_user(data):
    failed = data[data["status"] == "failed"]
    return failed.groupby("user").size()

def validator_agent(counts: pd.Series):
    return [(ip, tries) for ip, tries in counts.items() if tries > 3]

def reporter_agent(bad):
    if not bad:
        return "No threats. All good."
    text = "Suspicious IPs:\n"
    for ip, tries in bad:
        text += f"- {ip}: {tries} failed attempts\n"
    return text

# ✅ Option 3 — No API needed, no money needed!
def ai_summarize(report_text):
    if "No threats" in report_text:
        return "✅ All logins look normal. No action needed."

    lines = [l for l in report_text.strip().split("\n") if l.startswith("-")]
    count = len(lines)
    ip_list = [l.split(":")[0].replace("-", "").strip() for l in lines]
    ip_text = ", ".join(ip_list)

    return (
        f"🚨 {count} suspicious IP(s) detected: {ip_text} — "
        "these IPs had too many failed login attempts. "
        "Block them immediately and alert your security team!"
    )

# ── Streamlit UI ─────────────────────────────────────

st.title("🛡️ Threat Hunt SOC Analyst Agent")
st.markdown("Upload authentication logs → multi-agent system hunts for brute-force attacks.")

file = st.file_uploader("📁 Upload your log file", type="csv")

if file:
    data = pd.read_csv(file)

    # ✅ Column check
    required_cols = {"status", "ip", "user"}
    missing_cols = required_cols - set(data.columns)
    if missing_cols:
        st.error(f"❌ Your CSV is missing these columns: {missing_cols}")
        st.stop()

    st.write("📋 Log Preview:", data)

    # ✅ Session state fix
    if "results_ready" not in st.session_state:
        st.session_state.results_ready = False

    if st.button("🔍 Spy Hunt!"):
        st.session_state.results_ready = True

    if st.session_state.results_ready:

        hypo = hypothesis_agent()
        st.info(f"🧠 Agent 1 – Hypothesis: {hypo}")

        counts = analyst_agent(data)
        st.write("📊 Agent 2 – Failed logins per IP:")
        st.write(counts)

        user_counts = count_failed_per_user(data)
        st.write("👤 Agent 2b – Failed logins per User:")
        st.write(user_counts)

        if not counts.empty:
            st.bar_chart(counts)

        bad = validator_agent(counts)
        st.write("⚖️ Agent 3 – Validator:")

        if bad:
            st.error("🚨 Threat detected!")
        else:
            st.success("✅ No threat found.")

        report = reporter_agent(bad)
        st.write("📝 Agent 4 – Incident Report:")
        st.code(report)

        st.subheader("🤖 SOC Assistant Summary")
        summary = ai_summarize(report)
        st.success(summary)

