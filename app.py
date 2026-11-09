import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st
from scipy import stats


st.set_page_config(page_title="PacketWatch", page_icon="📡", layout="wide")

st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #07111f 0%, #101b2d 35%, #0d1726 100%);
            color: #edf4ff;
        }

        .stApp {
            background: linear-gradient(135deg, rgba(17,24,39,0.97), rgba(10,16,29,0.96));
        }

        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }

        div[data-testid="stMetricValue"] {
            font-size: 2rem;
            font-weight: 700;
        }

        .metric-card {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(96, 165, 250, 0.35);
            border-radius: 18px;
            padding: 1rem 1.1rem;
            box-shadow: 0 10px 30px rgba(59,130,246,0.12);
        }

        .section-header {
            color: #a5f3fc;
            font-weight: 800;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            margin-top: 1.25rem;
        }

        .glass-panel {
            background: rgba(15,23,42,0.8);
            border: 1px solid rgba(34,211,238,0.2);
            border-radius: 18px;
            padding: 1rem;
            box-shadow: 0 10px 25px rgba(14,165,233,0.08);
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def make_demo_dataset() -> pd.DataFrame:
    rng = np.random.default_rng(42)
    n_normal = 12000
    n_attack = 9000

    normal_packets = rng.lognormal(mean=2.2, sigma=1.0, size=n_normal)
    attack_packets = rng.lognormal(mean=3.4, sigma=1.15, size=n_attack)

    normal_df = pd.DataFrame(
        {
            "spkts": np.clip((normal_packets * 18).round().astype(int), 1, None),
            "dpkts": np.clip((normal_packets * 12).round().astype(int), 1, None),
            "dur": rng.gamma(shape=1.8, scale=0.8, size=n_normal),
            "sbytes": np.clip((normal_packets * 180).round().astype(int), 10, None),
            "dbytes": np.clip((normal_packets * 150).round().astype(int), 10, None),
            "proto": rng.choice(["tcp", "udp", "icmp", "arp", "http"], size=n_normal),
            "attack_cat": "normal",
            "label": 0,
        }
    )

    attack_df = pd.DataFrame(
        {
            "spkts": np.clip((attack_packets * 36).round().astype(int), 1, None),
            "dpkts": np.clip((attack_packets * 28).round().astype(int), 1, None),
            "dur": rng.gamma(shape=2.2, scale=1.4, size=n_attack),
            "sbytes": np.clip((attack_packets * 320).round().astype(int), 10, None),
            "dbytes": np.clip((attack_packets * 260).round().astype(int), 10, None),
            "proto": rng.choice(["tcp", "udp", "icmp", "arp", "http"], size=n_attack),
            "attack_cat": rng.choice(["DoS", "Reconnaissance", "Backdoor", "Analysis", "Fuzzers"], size=n_attack),
            "label": 1,
        }
    )

    return pd.concat([normal_df, attack_df], ignore_index=True)


def load_dataset() -> pd.DataFrame:
    csv_candidates = list(Path(".").rglob("*.csv"))
    csv_candidates = [p for p in csv_candidates if "sample" not in p.name.lower()]

    if csv_candidates:
        chosen = sorted(csv_candidates, key=lambda p: len(p.parts))[0]
        df = pd.read_csv(chosen)
        st.sidebar.success(f"Loaded dataset: {chosen}")
        return df

    st.sidebar.info("No CSV dataset found. Using a demo dataset for preview mode.")
    return make_demo_dataset()


def validate_columns(df: pd.DataFrame) -> pd.DataFrame:
    required = {"spkts", "dpkts", "dur", "sbytes", "dbytes", "proto", "attack_cat", "label"}
    missing = required - set(df.columns)
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(f"Dataset is missing required columns: {missing_list}")

    df = df.copy()
    for col in ["spkts", "dpkts", "dur", "sbytes", "dbytes", "label"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["total_packets"] = df["spkts"].fillna(0) + df["dpkts"].fillna(0)
    df["attack_group"] = np.where(df["label"].astype(int) == 1, "Malicious", "Normal")
    return df.dropna(subset=["spkts", "dpkts", "dur", "sbytes", "dbytes", "label"]).reset_index(drop=True)


def summary_stats_for_group(values: pd.Series) -> dict:
    return {
        "count": int(len(values)),
        "mean": float(values.mean()),
        "median": float(values.median()),
        "std": float(values.std(ddof=1)) if len(values) > 1 else 0.0,
        "min": float(values.min()),
        "max": float(values.max()),
    }


def cohen_d(x, y):
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    pooled = math.sqrt(((len(x) - 1) * np.var(x, ddof=1) + (len(y) - 1) * np.var(y, ddof=1)) / (len(x) + len(y) - 2))
    if pooled == 0:
        return 0.0
    return (x.mean() - y.mean()) / pooled


def plot_pie_chart(df):
    counts = df["attack_group"].value_counts()
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.pie(
        counts.values,
        labels=[f"{k} ({v})" for k, v in counts.items()],
        colors=["#38bdf8", "#fb7185"],
        startangle=90,
        wedgeprops={"edgecolor": "#0f172a", "linewidth": 2},
    )
    ax.set_title("Traffic composition", color="#e2e8f0", fontsize=14)
    return fig


def plot_average_bar(df):
    group_stats = df.groupby("attack_group")["total_packets"].agg(["mean", "median"])
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(group_stats))
    ax.bar(x - 0.18, group_stats["mean"], width=0.35, color="#38bdf8", label="Average")
    ax.bar(x + 0.18, group_stats["median"], width=0.35, color="#a78bfa", label="Median")
    ax.set_xticks(x, group_stats.index)
    ax.set_ylabel("Packets")
    ax.set_title("Average vs median packet count", color="#e2e8f0")
    ax.legend()
    ax.grid(axis="y", alpha=0.2)
    return fig


def plot_boxplot(df):
    fig, ax = plt.subplots(figsize=(8, 5))
    df.boxplot(column="total_packets", by="attack_group", ax=ax, patch_artist=True, return_type="axes")
    ax.set_title("Packet count distribution by traffic class")
    ax.set_xlabel("Traffic class")
    ax.set_ylabel("Total packets")
    for patch in ax.artists:
        patch.set_facecolor("#38bdf8")
    return fig


def plot_protocols(df):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, group_name in zip(axes, ["Normal", "Malicious"]):
        subset = df[df["attack_group"] == group_name]
        top = subset["proto"].value_counts().head(6)
        ax.barh(top.index[::-1], top.values[::-1], color="#38bdf8" if group_name == "Normal" else "#fb7185")
        ax.set_title(f"Top protocols: {group_name}")
        ax.set_xlabel("Count")
        ax.invert_yaxis()
    return fig


def plot_bytes_and_duration(df):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    group_summary = df.groupby("attack_group").agg({"dur": "mean", "sbytes": "mean", "dbytes": "mean"})
    labels = group_summary.index
    axes[0].bar(labels, group_summary["dur"], color=["#38bdf8", "#fb7185"])
    axes[0].set_title("Mean connection duration")
    axes[0].set_ylabel("Seconds")

    bytes_data = group_summary[["sbytes", "dbytes"]]
    bytes_data.plot(kind="bar", ax=axes[1], color=["#60a5fa", "#f472b6"])
    axes[1].set_title("Mean bytes sent vs received")
    axes[1].set_ylabel("Bytes")
    axes[1].legend(["Bytes sent", "Bytes received"])
    return fig


def main():
    st.markdown('<div class="section-header">Traffic intelligence dashboard</div>', unsafe_allow_html=True)
    st.title("PacketWatch")
    st.caption("Statistical comparison of normal traffic against malicious traffic in the UNSW-NB15 dataset.")

    try:
        df = validate_columns(load_dataset())
    except ValueError as exc:
        st.error(str(exc))
        st.stop()

    normal = df[df["attack_group"] == "Normal"]["total_packets"]
    malicious = df[df["attack_group"] == "Malicious"]["total_packets"]

    normal_summary = summary_stats_for_group(normal)
    malicious_summary = summary_stats_for_group(malicious)

    with st.sidebar:
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        st.header("Controls")
        sample_size = st.slider("Preview sample size", min_value=500, max_value=min(5000, len(df)), value=min(2000, len(df)), step=250)
        st.caption(f"Working with {len(df):,} records.")
        st.markdown("</div>", unsafe_allow_html=True)

    df_preview = df.sample(n=min(sample_size, len(df)), random_state=42)

    metric_cols = st.columns(4)
    metric_cols[0].markdown(
        f"""
        <div class='metric-card'>
            <div style='color:#94a3b8; font-size:0.8rem;'>Normal records</div>
            <div>{normal_summary['count']:,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    metric_cols[1].markdown(
        f"""
        <div class='metric-card'>
            <div style='color:#94a3b8; font-size:0.8rem;'>Malicious records</div>
            <div>{malicious_summary['count']:,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    metric_cols[2].markdown(
        f"""
        <div class='metric-card'>
            <div style='color:#94a3b8; font-size:0.8rem;'>Normal avg packets</div>
            <div>{normal_summary['mean']:.1f}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    metric_cols[3].markdown(
        f"""
        <div class='metric-card'>
            <div style='color:#94a3b8; font-size:0.8rem;'>Malicious avg packets</div>
            <div>{malicious_summary['mean']:.1f}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-header">Overview</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([1.15, 1.35])
    col1.pyplot(plot_pie_chart(df_preview), use_container_width=True)
    col2.pyplot(plot_average_bar(df_preview), use_container_width=True)

    st.markdown('<div class="section-header">Distribution analysis</div>', unsafe_allow_html=True)
    col3, col4 = st.columns(2)
    col3.pyplot(plot_boxplot(df_preview), use_container_width=True)
    col4.pyplot(plot_bytes_and_duration(df_preview), use_container_width=True)

    st.markdown('<div class="section-header">Protocol behavior</div>', unsafe_allow_html=True)
    st.pyplot(plot_protocols(df_preview), use_container_width=True)

    st.markdown('<div class="section-header">Hypothesis test</div>', unsafe_allow_html=True)
    t_stat, p_value = stats.ttest_ind(normal, malicious, equal_var=False)
    effect_size = cohen_d(normal, malicious)
    significant = p_value < 0.05

    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
    stat_col1.metric("t statistic", f"{t_stat:.3f}")
    stat_col2.metric("p-value", f"{p_value:.6g}")
    stat_col3.metric("Cohen's d", f"{effect_size:.3f}")
    stat_col4.metric("Decision", "Reject H₀" if significant else "Fail to reject H₀")

    st.markdown(
        """
        <div class='glass-panel'>
            <strong>Interpretation:</strong>
            The Welch t-test compares the mean total packet counts between normal and malicious traffic.
            A small p-value suggests the difference is statistically significant, while Cohen's d shows whether the difference is practically meaningful.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-header">Descriptive statistics</div>', unsafe_allow_html=True)
    summary_df = pd.DataFrame(
        {
            "Group": ["Normal", "Malicious"],
            "Records": [normal_summary["count"], malicious_summary["count"]],
            "Mean": [normal_summary["mean"], malicious_summary["mean"]],
            "Median": [normal_summary["median"], malicious_summary["median"]],
            "Std Dev": [normal_summary["std"], malicious_summary["std"]],
            "Min": [normal_summary["min"], malicious_summary["min"]],
            "Max": [normal_summary["max"], malicious_summary["max"]],
        }
    )
    st.dataframe(summary_df.style.format({"Mean": "{:.2f}", "Median": "{:.2f}", "Std Dev": "{:.2f}", "Min": "{:.2f}", "Max": "{:.2f}"}), use_container_width=True)

    if significant:
        st.success("The difference in mean packet count is statistically significant at α = 0.05.")
    else:
        st.warning("The difference in mean packet count is not statistically significant at α = 0.05.")


if __name__ == "__main__":
    main()
