#!/usr/bin/env bash
#
# generate_traffic.sh
# ชุดสคริปต์สำหรับสร้าง Traffic ทั้งแบบปกติ (Normal) และผิดปกติ (Abnormal)
# รองรับการทำ Automated Experiment พร้อมบันทึก Ground Truth Timeline
#

set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-8080}"
ACTION="${3:-help}"

function show_usage() {
    echo "=========================================================="
    echo "  Traffic Generator & Benchmark Suite"
    echo "=========================================================="
    echo "วิธีใช้: $0 [host] [port] <action>"
    echo ""
    echo "Actions:"
    echo "  server                   : เปิด dummy HTTP server รอรับการเชื่อมต่อ"
    echo "  normal <count>           : ยิง TCP connection ปกติ (เช่น curl)"
    echo "  syn-flood <count>        : จำลอง SYN Flood ด้วย hping3 (ต้อง sudo)"
    echo "  port-scan                : จำลอง Incomplete Handshakes (Port Scanning)"
    echo "  auto-benchmark <out_dir> : รันชุดการทดลองอัตโนมัติ (Normal -> Latency -> SYN Flood)"
    echo ""
    echo "ตัวอย่าง:"
    echo "  $0 127.0.0.1 8080 normal 20"
    echo "  sudo $0 127.0.0.1 8080 syn-flood 500"
    echo "  $0 127.0.0.1 8080 auto-benchmark data/"
    echo "=========================================================="
}

case "$ACTION" in
    server)
        echo "🌐 กำลังเปิด Dummy HTTP Server บน $TARGET_HOST:$TARGET_PORT ..."
        python3 -m http.server "$TARGET_PORT" --bind "$TARGET_HOST"
        ;;

    normal)
        COUNT="${4:-30}"
        echo "🚀 กำลังส่ง Normal TCP Traffic จำนวน $COUNT ครั้ง ไปยัง $TARGET_HOST:$TARGET_PORT ..."
        for ((i=1; i<=COUNT; i++)); do
            curl -s -m 2 "http://$TARGET_HOST:$TARGET_PORT/" >/dev/null || true
            sleep 0.1
        done
        echo "✔ ยิง Normal Traffic เสร็จสิ้น!"
        ;;

    syn-flood)
        COUNT="${4:-500}"
        echo "⚠️ กำลังจำลอง SYN Flood (hping3) จำนวน $COUNT แพ็กเก็ต ไปยัง $TARGET_HOST:$TARGET_PORT ..."
        if ! command -v hping3 &>/dev/null; then
            echo "❌ ไม่พบคำสั่ง hping3 กรุณาติดตั้งด้วย: sudo apt-get install hping3"
            exit 1
        fi
        sudo hping3 -S -p "$TARGET_PORT" -c "$COUNT" -i u2000 "$TARGET_HOST" >/dev/null 2>&1 || true
        echo "✔ ยิง SYN Flood เสร็จสิ้น!"
        ;;

    port-scan)
        echo "🔍 กำลังจำลอง Incomplete Handshakes (Port Scanning) ไปยัง 50 พอร์ตแบบสุ่ม..."
        for port in {9000..9050}; do
            timeout 0.1 bash -c "cat < /dev/null > /dev/tcp/$TARGET_HOST/$port" 2>/dev/null || true
        done
        echo "✔ สแกนพอร์ตเสร็จสิ้น!"
        ;;

    auto-benchmark)
        OUT_DIR="${4:-./benchmark_data}"
        mkdir -p "$OUT_DIR"
        TIMELINE_FILE="$OUT_DIR/ground_truth_timeline.csv"

        echo "Timestamp,Label,Description" > "$TIMELINE_FILE"
        echo "🧪 กำลังเริ่มกระบวนการทดสอบอัตโนมัติ (Automated Benchmark Suite)..."
        echo "📁 ข้อมูลจะถูกบันทึกไว้ใน: $OUT_DIR"

        # เฟสที่ 1: Normal Traffic Baseline (20 วินาที)
        NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "$NOW,NORMAL,Normal traffic baseline" >> "$TIMELINE_FILE"
        echo "▶ [Phase 1/4] สร้าง Normal Traffic (Baseline 15s)..."
        for i in {1..25}; do
            curl -s -m 2 "http://$TARGET_HOST:$TARGET_PORT/" >/dev/null || true
            sleep 0.5
        done

        # เฟสที่ 2: Injected Latency (15 วินาที)
        NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "$NOW,HIGH_LATENCY,Injecting 100ms delay via tc" >> "$TIMELINE_FILE"
        echo "▶ [Phase 2/4] จำลอง High Latency (100ms delay 15s)..."
        if [[ $EUID -eq 0 ]]; then
            tc qdisc add dev lo root netem delay 100ms 2>/dev/null || true
        fi
        for i in {1..15}; do
            curl -s -m 2 "http://$TARGET_HOST:$TARGET_PORT/" >/dev/null || true
            sleep 0.5
        done
        if [[ $EUID -eq 0 ]]; then
            tc qdisc del dev lo root 2>/dev/null || true
        fi

        # เฟสที่ 3: Injected Packet Loss (15 วินาที)
        NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "$NOW,PACKET_LOSS,Injecting 10% packet loss via tc" >> "$TIMELINE_FILE"
        echo "▶ [Phase 3/4] จำลอง Packet Loss (10% loss ทำให้เกิด Retransmissions)..."
        if [[ $EUID -eq 0 ]]; then
            tc qdisc add dev lo root netem loss 10% 2>/dev/null || true
        fi
        for i in {1..15}; do
            curl -s -m 2 "http://$TARGET_HOST:$TARGET_PORT/" >/dev/null || true
            sleep 0.5
        done
        if [[ $EUID -eq 0 ]]; then
            tc qdisc del dev lo root 2>/dev/null || true
        fi

        # เฟสที่ 4: Port Scan / Incomplete Handshakes
        NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "$NOW,INCOMPLETE_HANDSHAKE,Scanning closed ports" >> "$TIMELINE_FILE"
        echo "▶ [Phase 4/4] จำลอง Incomplete Handshakes (Port Scanning)..."
        for port in {9100..9140}; do
            timeout 0.05 bash -c "cat < /dev/null > /dev/tcp/$TARGET_HOST/$port" 2>/dev/null || true
        done

        NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "$NOW,END,Experiment finished" >> "$TIMELINE_FILE"
        echo "✔ การทดลองอัตโนมัติเสร็จสิ้นเรียบร้อย! Timeline บันทึกที่: $TIMELINE_FILE"
        ;;

    *)
        show_usage
        exit 1
        ;;
esac
