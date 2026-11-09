# PacketWatch

A sleek Streamlit dashboard for comparing normal and malicious network traffic using the UNSW-NB15-inspired packet statistics model.

## Features
- Dark, modern dashboard styling
- Packet-count comparison for normal vs malicious traffic
- Descriptive statistics tables
- Welch's t-test and Cohen's d reporting
- Protocol distribution and duration/byte comparisons
- Demo mode when no CSV dataset is present

## Run locally

1. Create a virtual environment (optional but recommended)
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the app:
   ```bash
   streamlit run app.py
   ```

## Data
- The app looks for CSV files in the workspace automatically.
- If no dataset is available, it generates a demo dataset so the dashboard still works.
- For the real UNSW-NB15 analysis, place the CSV file in the project folder and restart the app.
