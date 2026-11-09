# PacketWatch

A custom web dashboard for comparing normal and malicious network traffic in UNSW-NB15.
The interface is plain HTML, CSS, and JavaScript; Python serves the dashboard and its analysis API.
The single-screen interface has animated tabs for a rotatable 3D traffic map, packet-volume columns,
protocol signatures, and a paginated flow log. Drag the 3D scenes to rotate and use the wheel to zoom.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:8501`. In a remote VS Code workspace, forward port `8501` from the Ports panel.

## Data

Place the UNSW-NB15 training/testing CSV files next to `app.py` or in `data/`. The app merges
matching files and removes duplicate records (ignoring the `id` column). Without a valid dataset,
it displays synthetic demo data. Dataset CSVs are git-ignored due to their size.

## Analysis

The dashboard compares `spkts + dpkts` for labels 0 (normal) and 1 (malicious), and reports Welch's
two-tailed independent-samples t-test, Cohen's d, and a confidence interval. Display controls do not
change the records used by the hypothesis test.

## Limitations

UNSW-NB15 contains simulated attacks and an artificial class balance. Flows may not be independent;
results describe this dataset and do not establish packet count as a useful detection feature.

## Citations

- Moustafa, N., & Slay, J. (2015). UNSW-NB15: A comprehensive data set for network intrusion detection systems. MilCIS, IEEE.
- Moustafa, N., & Slay, J. (2016). The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set. Information Security Journal: A Global Perspective, 1-14.
