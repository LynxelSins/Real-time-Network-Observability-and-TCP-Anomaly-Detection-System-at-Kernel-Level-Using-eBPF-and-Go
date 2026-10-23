#!/usr/bin/env bash
#
# measure_overhead.sh
# เครื่องมือวัด System Overhead & Resource Utilization ขณะที่ eBPF ทำงาน
# บันทึก CPU %, Memory (RSS/VSZ) และ Kernel BPF Runtime Stats
#

PID="${1:-}"
DURATION="${2:-10}"
OUT_FILE="${3:-benchmark_data/overhead_stats.csv}"

if [[ -z "$PID" ]]; then
    echo "วิธีใช้: $0 <PID_of_tcp_monitor> [duration_seconds] [output_csv]"
    echo "ตัวอย่าง: $0 \$(pgrep tcp_monitor) 15"
    exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"
echo "Timestamp,CPU_Percent,Memory_KB" > "$OUT_FILE"

echo "⏱ กำลังวัด System Overhead ของ PID $PID เป็นเวลา $DURATION วินาที..."
for ((i=1; i<=DURATION; i++)); do
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "❌ Process $PID สิ้นสุดการทำงานแล้ว"
        break
    fi

    NOW=$(date +"%H:%M:%S")
    # อ่าน CPU % และ RSS Memory (KB) จาก ps
    STATS=$(ps -p "$PID" -o %cpu,rss --no-headers | awk '{print $1","$2}')
    echo "$NOW,$STATS" >> "$OUT_FILE"
    sleep 1
done

echo "✔ บันทึกผล Overhead ที่: $OUT_FILE"
echo "📊 ค่าเฉลี่ยการใช้ทรัพยากร:"
awk -F',' 'NR>1 {cpu+=$2; mem+=$3; n++} END {if (n>0) printf "  CPU: %.2f%% | RSS Memory: %.2f MB\n", cpu/n, (mem/n)/1024}' "$OUT_FILE"
