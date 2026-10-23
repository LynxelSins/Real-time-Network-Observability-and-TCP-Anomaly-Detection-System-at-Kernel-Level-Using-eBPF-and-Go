#!/usr/bin/env bash
#
# simulate_impairment.sh
# เครื่องมือสำหรับจำลองสภาพแวดล้อมเครือข่ายผิดปกติด้วย Linux Traffic Control (tc netem)
# ใช้สำหรับสร้าง Controlled Experiment เพื่อทดสอบ Handshake Latency และ Packet Loss
#

set -euo pipefail

INTERFACE="${1:-lo}"
ACTION="${2:-help}"

function show_usage() {
    echo "=========================================================="
    echo "  Linux Network Impairment Tool (tc netem)"
    echo "=========================================================="
    echo "วิธีใช้: sudo $0 <interface> <action>"
    echo ""
    echo "Actions:"
    echo "  delay <ms> [jitter_ms]    : ใส่ความล่าช้า (เช่น delay 100ms 10ms)"
    echo "  loss <percent>            : ใส่ Packet Loss (เช่น loss 5%)"
    echo "  delay-loss <ms> <percent> : ใส่ทั้ง Delay และ Loss พร้อมกัน"
    echo "  status                    : ตรวจสอบสถานะ qdisc ปัจจุบัน"
    echo "  reset                     : ยกเลิกการจำลอง คืนค่าเครือข่ายสู่ภาวะปกติ"
    echo ""
    echo "ตัวอย่าง:"
    echo "  sudo $0 lo delay 100ms 10ms"
    echo "  sudo $0 lo loss 10%"
    echo "  sudo $0 lo reset"
    echo "=========================================================="
}

if [[ $EUID -ne 0 ]]; then
   echo "❌ กรุณารันสคริปต์นี้ด้วยสิทธิ์ root (sudo $0 ...)" 
   exit 1
fi

case "$ACTION" in
    delay)
        MS="${3:-100ms}"
        JITTER="${4:-}"
        echo "🔧 กำลังตั้งค่า Latency บน '$INTERFACE' เป็น $MS $JITTER ..."
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        if [[ -n "$JITTER" ]]; then
            tc qdisc add dev "$INTERFACE" root netem delay "$MS" "$JITTER"
        else
            tc qdisc add dev "$INTERFACE" root netem delay "$MS"
        fi
        echo "✔ ตั้งค่าสำเร็จ!"
        ;;

    loss)
        PCT="${3:-5%}"
        echo "🔧 กำลังตั้งค่า Packet Loss บน '$INTERFACE' เป็น $PCT ..."
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        tc qdisc add dev "$INTERFACE" root netem loss "$PCT"
        echo "✔ ตั้งค่าสำเร็จ!"
        ;;

    delay-loss)
        MS="${3:-100ms}"
        PCT="${4:-5%}"
        echo "🔧 กำลังตั้งค่า Delay $MS และ Loss $PCT บน '$INTERFACE' ..."
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        tc qdisc add dev "$INTERFACE" root netem delay "$MS" loss "$PCT"
        echo "✔ ตั้งค่าสำเร็จ!"
        ;;

    status)
        echo "📊 สถานะ qdisc ปัจจุบันของ '$INTERFACE':"
        tc -s qdisc show dev "$INTERFACE"
        ;;

    reset)
        echo "🔄 กำลังยกเลิกการจำลอง คืนค่า '$INTERFACE' สู่ภาวะปกติ..."
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        echo "✔ เครือข่ายกลับสู่สภาวะปกติเรียบร้อยแล้ว!"
        ;;

    *)
        show_usage
        exit 1
        ;;
esac
