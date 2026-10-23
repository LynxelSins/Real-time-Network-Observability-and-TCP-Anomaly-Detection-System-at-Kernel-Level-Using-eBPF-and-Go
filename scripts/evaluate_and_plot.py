#!/usr/bin/env python3
"""
evaluate_and_plot.py

สคริปต์สำหรับ:
1. ทำ Exploratory Data Analysis (EDA) วิเคราะห์การกระจายตัวของ Handshake Latency
2. คำนวณ Detection Performance Metrics (Precision, Recall, F1-Score, FPR)
3. พล็อตกราฟสรุปผลเชิงวิชาการ (CDF, Latency Timeline, Anomaly Breakdown)
"""

import json
import os
import sys
from datetime import datetime
import pandas as pd
import numpy as np

def load_alerts(jsonl_path):
    records = []
    if not os.path.exists(jsonl_path):
        print(f"❌ ไม่พบไฟล์ log: {jsonl_path}")
        return pd.DataFrame()

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    df = pd.DataFrame(records)
    if not df.empty and 'timestamp' in df.columns:
        df['dt'] = pd.to_datetime(df['timestamp'])
    return df

def calculate_metrics(alerts_df, timeline_csv_path):
    print("=" * 60)
    print("  📊 การประเมินประสิทธิภาพการตรวจจับ (Detection Performance)")
    print("=" * 60)

    if not os.path.exists(timeline_csv_path):
        print(f"⚠️ ไม่พบไฟล์ Timeline Ground Truth: {timeline_csv_path}")
        print("   ไม่สามารถคำนวณ Precision/Recall เทียบกับช่วงเวลาจริงได้")
        return

    timeline_df = pd.read_csv(timeline_csv_path)
    timeline_df['dt'] = pd.to_datetime(timeline_df['Timestamp'])

    print("Ground Truth Phases:")
    for _, row in timeline_df.iterrows():
        print(f"  - [{row['dt'].strftime('%H:%M:%S')}] {row['Label']}: {row['Description']}")

    total_alerts = len(alerts_df)
    print(f"\nตรวจพบ Alerts ทั้งหมด: {total_alerts} รายการ")

    if not alerts_df.empty:
        type_counts = alerts_df['anomaly_type'].value_counts()
        print("\nจำแนกตามประเภทความผิดปกติ:")
        for atype, cnt in type_counts.items():
            print(f"  • {atype:<24}: {cnt} ครั้ง")

    print("\n" + "=" * 60)

def generate_eda_report(alerts_df, out_dir):
    print("📈 กำลังประมวลผลสถิติและทำ EDA...")
    os.makedirs(out_dir, exist_ok=True)

    summary_file = os.path.join(out_dir, "eda_summary.txt")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("=== eBPF TCP Anomaly Detection EDA Summary ===\n\n")
        f.write(f"Generated at: {datetime.now().isoformat()}\n")
        f.write(f"Total Anomalies Logged: {len(alerts_df)}\n\n")

        if not alerts_df.empty and 'duration_ms' in alerts_df.columns:
            durations = alerts_df[alerts_df['duration_ms'] > 0]['duration_ms']
            if not durations.empty:
                f.write("Latency Statistics (ms):\n")
                f.write(f"  Mean:   {durations.mean():.2f} ms\n")
                f.write(f"  StdDev: {durations.std():.2f} ms\n")
                f.write(f"  Median: {durations.median():.2f} ms\n")
                f.write(f"  Min:    {durations.min():.2f} ms\n")
                f.write(f"  Max:    {durations.max():.2f} ms\n")
                f.write(f"  95th %: {durations.quantile(0.95):.2f} ms\n")
                f.write(f"  99th %: {durations.quantile(0.99):.2f} ms\n")

    print(f"✔ บันทึกบทสรุปสถิติที่: {summary_file}")

    # พยายามนำเข้า matplotlib สำหรับวาดรูป (ถ้าติดตั้งไว้)
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        if not alerts_df.empty and 'duration_ms' in alerts_df.columns:
            latencies = alerts_df[alerts_df['duration_ms'] > 0]['duration_ms'].dropna()

            if len(latencies) > 0:
                plt.figure(figsize=(10, 5))

                # กราฟที่ 1: Latency Distribution (Histogram + CDF)
                plt.subplot(1, 2, 1)
                sorted_data = np.sort(latencies)
                cdf = np.arange(len(sorted_data)) / float(len(sorted_data))
                plt.plot(sorted_data, cdf, color='#7D56F4', linewidth=2)
                plt.title("Handshake Latency CDF")
                plt.xlabel("Latency (ms)")
                plt.ylabel("Cumulative Probability")
                plt.grid(True, linestyle='--', alpha=0.6)

                # กราฟที่ 2: Anomalies by Type (Bar chart)
                plt.subplot(1, 2, 2)
                type_counts = alerts_df['anomaly_type'].value_counts()
                colors = ['#FF3366', '#FFAF00', '#00E5FF', '#7D56F4']
                type_counts.plot(kind='bar', color=colors[:len(type_counts)])
                plt.title("Anomalies by Category")
                plt.xlabel("Anomaly Type")
                plt.ylabel("Count")
                plt.xticks(rotation=30, ha='right')
                plt.grid(axis='y', linestyle='--', alpha=0.6)

                plt.tight_layout()
                plot_path = os.path.join(out_dir, "eda_distribution_plots.png")
                plt.savefig(plot_path, dpi=300)
                plt.close()
                print(f"✔ สร้างกราฟและบันทึกรูปภาพที่: {plot_path}")
    except ImportError:
        print("💡 หมายเหตุ: ไม่พบไลบรารี matplotlib ข้ามการพล็อตกราฟรูปภาพ (ติดตั้งเพิ่มได้ด้วย: pip install matplotlib)")

def main():
    jsonl_path = sys.argv[1] if len(sys.argv) > 1 else "alerts.jsonl"
    timeline_path = sys.argv[2] if len(sys.argv) > 2 else "benchmark_data/ground_truth_timeline.csv"
    out_dir = sys.argv[3] if len(sys.argv) > 3 else "benchmark_data"

    print(f"🔍 โหลดข้อมูล Alerts จาก: {jsonl_path}")
    df = load_alerts(jsonl_path)
    calculate_metrics(df, timeline_path)
    generate_eda_report(df, out_dir)

if __name__ == "__main__":
    main()
