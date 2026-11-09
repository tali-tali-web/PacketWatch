"""PacketWatch's data API and static web server."""
import glob
import json
import math
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np
import pandas as pd
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("PACKETWATCH_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8501"))
NEEDED = ["spkts", "dpkts", "dur", "sbytes", "dbytes", "proto", "label"]
NUMERIC = ["spkts", "dpkts", "dur", "sbytes", "dbytes", "label"]


def synthetic_data(n=20000, seed=42):
    rng = np.random.default_rng(seed)
    label = (rng.random(n) < 0.55).astype(int)
    spkts = np.where(label == 1, rng.lognormal(2.4, 1.2, n), rng.lognormal(2.0, 1.0, n)).astype(int) + 1
    dpkts = np.where(label == 1, rng.lognormal(1.4, 1.5, n), rng.lognormal(1.9, 1.0, n)).astype(int)
    return pd.DataFrame({
        "spkts": spkts,
        "dpkts": dpkts,
        "dur": np.where(label == 1, rng.lognormal(-3, 2.5, n), rng.lognormal(-2, 2.0, n)),
        "sbytes": spkts * rng.integers(40, 900, n),
        "dbytes": dpkts * rng.integers(40, 1400, n),
        "proto": rng.choice(
            ["tcp", "udp", "icmp", "arp", "ospf", "sctp"], n,
            p=[.55, .30, .06, .04, .03, .02],
        ),
        "label": label,
        "attack_cat": np.where(
            label == 1, rng.choice(["Generic", "Exploits", "Fuzzers", "DoS"], n), "Normal"
        ),
    })


def load_data():
    paths = sorted(
        glob.glob(os.path.join(HERE, "*.csv"))
        + glob.glob(os.path.join(HERE, "data", "*.csv"))
    )
    frames, issues = [], []
    for path in paths:
        try:
            frame = pd.read_csv(path)
        except (OSError, UnicodeDecodeError, pd.errors.ParserError) as exc:
            issues.append(f"{os.path.basename(path)} could not be read: {exc}")
            continue
        frame.columns = [column.strip().lower() for column in frame.columns]
        if not all(column in frame.columns for column in NEEDED):
            continue
        for column in NUMERIC:
            frame[column] = pd.to_numeric(frame[column], errors="coerce")
        numeric = frame[NUMERIC]
        valid = np.isfinite(numeric).all(axis=1)
        valid &= frame["label"].isin([0, 1])
        valid &= (frame[["spkts", "dpkts", "dur", "sbytes", "dbytes"]] >= 0).all(axis=1)
        dropped = int((~valid).sum())
        if dropped:
            issues.append(f"{os.path.basename(path)}: skipped {dropped:,} invalid row(s)")
        frame = frame.loc[valid].copy()
        if not frame.empty:
            frame["source_file"] = os.path.basename(path)
            frames.append(frame)

    if not frames:
        return synthetic_data(), "Synthetic demo data", 0, issues

    data = pd.concat(frames, ignore_index=True)
    before = len(data)
    subset = [column for column in data.columns if column not in ("id", "source_file")]
    data = data.drop_duplicates(subset=subset).reset_index(drop=True)
    return data, f"UNSW-NB15 · {len(frames)} file(s)", before - len(data), issues


DATA, SOURCE, DUPLICATES, ISSUES = load_data()
DATA["total_packets"] = DATA["spkts"] + DATA["dpkts"]
DATA["group"] = DATA["label"].map({0: "Normal", 1: "Malicious"})
if any((DATA["label"] == label).sum() < 2 for label in (0, 1)):
    raise ValueError("Dataset must contain at least two valid records for each label (0 and 1).")


def group_values(column):
    return {
        group: DATA.loc[DATA["group"] == group, column].astype(float)
        for group in ("Normal", "Malicious")
    }


def describe(values):
    return {
        "count": int(values.size),
        "mean": float(values.mean()),
        "median": float(values.median()),
        "std": float(values.std(ddof=1)),
        "min": float(values.min()),
        "max": float(values.max()),
        "skew": float(values.skew()) if values.size > 2 else 0.0,
    }


def packet_distribution(log_scale):
    grouped = group_values("total_packets")
    maximum = max(float(values.max()) for values in grouped.values())
    edges = (
        np.geomspace(1, max(2, maximum + 1), 15)
        if log_scale else np.linspace(0, maximum + 1, 15)
    )
    series = {}
    for group, values in grouped.items():
        counts, _ = np.histogram(values, bins=edges)
        series[group.lower()] = (counts / len(values) * 100).round(3).tolist()
    return {
        "edges": edges.round(3).tolist(),
        "normal": series["normal"],
        "malicious": series["malicious"],
    }


def box_summaries():
    result = {}
    for group, values in group_values("total_packets").items():
        low, q1, median, q3, high = np.percentile(values, [5, 25, 50, 75, 95])
        result[group.lower()] = [float(value) for value in (low, q1, median, q3, high)]
    return result


def hypothesis(alpha):
    normal, malicious = group_values("total_packets").values()
    test = stats.ttest_ind(normal, malicious, equal_var=False)
    n1, n2 = len(normal), len(malicious)
    mean_diff = float(normal.mean() - malicious.mean())
    v1, v2 = normal.var(ddof=1), malicious.var(ddof=1)
    se2 = v1 / n1 + v2 / n2
    dof = se2**2 / ((v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1))
    margin = stats.t.ppf(1 - alpha / 2, dof) * math.sqrt(se2)
    pooled = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
    effect = mean_diff / pooled if pooled else 0.0
    magnitude = abs(effect)
    size = "negligible" if magnitude < .2 else "small" if magnitude < .5 else "medium" if magnitude < .8 else "large"
    return {
        "t": float(test.statistic),
        "p": float(test.pvalue),
        "alpha": alpha,
        "difference": mean_diff,
        "ci": [mean_diff - margin, mean_diff + margin],
        "cohens_d": float(effect),
        "effect": size,
        "significant": bool(test.pvalue < alpha),
    }


def dashboard(params):
    alpha = float(params.get("alpha", ["0.05"])[0])
    top_n = int(params.get("top_n", ["6"])[0])
    page = int(params.get("page", ["1"])[0])
    page_size = int(params.get("page_size", ["10"])[0])
    group = params.get("group", ["All"])[0]
    aggregation = params.get("aggregation", ["median"])[0]
    log_value = params.get("log_scale", ["true"])[0].lower()
    if alpha not in (.01, .05, .1):
        raise ValueError("Significance level must be 0.01, 0.05, or 0.10.")
    if not 3 <= top_n <= 12:
        raise ValueError("Protocol count must be between 3 and 12.")
    if page < 1 or page_size not in (5, 10, 20, 50):
        raise ValueError("Page or page size is out of range.")
    if group not in ("All", "Normal", "Malicious"):
        raise ValueError("Traffic group must be All, Normal, or Malicious.")
    if aggregation not in ("mean", "median"):
        raise ValueError("Aggregation must be mean or median.")
    if log_value not in ("true", "false"):
        raise ValueError("Log scale must be true or false.")

    selected = DATA if group == "All" else DATA.loc[DATA["group"] == group]
    start = (page - 1) * page_size
    columns = [
        column for column in (
            "proto", "service", "state", "spkts", "dpkts", "total_packets", "dur",
            "sbytes", "dbytes", "attack_cat", "group",
        ) if column in selected.columns
    ]
    records = selected.iloc[start:start + page_size][columns].replace({np.nan: None}).to_dict("records")
    protocol_counts = pd.crosstab(DATA["group"], DATA["proto"])
    top_protocols = protocol_counts.sum().nlargest(top_n).index.tolist()
    collapsed = DATA["proto"].where(DATA["proto"].isin(top_protocols), "other")
    protocol_share = pd.crosstab(DATA["group"], collapsed, normalize="index").mul(100)
    protocol_share = protocol_share.reindex(columns=top_protocols + (["other"] if "other" in protocol_share else []), fill_value=0)

    duration = group_values("dur")
    bytes_sent = group_values("sbytes")
    bytes_received = group_values("dbytes")
    return {
        "source": SOURCE,
        "issues": ISSUES,
        "duplicates": DUPLICATES,
        "counts": {
            "all": int(len(DATA)),
            "normal": int((DATA["label"] == 0).sum()),
            "malicious": int((DATA["label"] == 1).sum()),
        },
        "packets": {key.lower(): describe(values) for key, values in group_values("total_packets").items()},
        "duration": {key.lower(): float(getattr(values, aggregation)()) for key, values in duration.items()},
        "bytes": {
            "normal": [float(getattr(bytes_sent["Normal"], aggregation)()), float(getattr(bytes_received["Normal"], aggregation)())],
            "malicious": [float(getattr(bytes_sent["Malicious"], aggregation)()), float(getattr(bytes_received["Malicious"], aggregation)())],
        },
        "distribution": packet_distribution(log_value == "true"),
        "box": box_summaries(),
        "protocols": {
            "names": protocol_share.columns.tolist(),
            "normal": protocol_share.loc["Normal"].round(3).tolist(),
            "malicious": protocol_share.loc["Malicious"].round(3).tolist(),
        },
        "test": hypothesis(alpha),
        "table": {
            "page": page,
            "page_size": page_size,
            "pages": max(1, math.ceil(len(selected) / page_size)),
            "total": int(len(selected)),
            "records": records,
        },
    }


class PacketWatchHandler(BaseHTTPRequestHandler):
    def send_body(self, body, content_type, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        request = urlparse(self.path)
        if request.path == "/api/dashboard":
            try:
                body = json.dumps(dashboard(parse_qs(request.query)), allow_nan=False).encode()
            except (ValueError, OverflowError) as exc:
                self.send_body(json.dumps({"error": str(exc)}).encode(), "application/json", 400)
                return
            self.send_body(body, "application/json; charset=utf-8")
            return

        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        asset = assets.get(request.path)
        if not asset:
            self.send_body(b"Not found", "text/plain; charset=utf-8", 404)
            return
        path, content_type = asset
        try:
            with open(os.path.join(HERE, "web", path), "rb") as file:
                self.send_body(file.read(), content_type)
        except OSError:
            self.send_body(b"Dashboard asset unavailable", "text/plain; charset=utf-8", 500)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    print(f"PacketWatch running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), PacketWatchHandler).serve_forever()
