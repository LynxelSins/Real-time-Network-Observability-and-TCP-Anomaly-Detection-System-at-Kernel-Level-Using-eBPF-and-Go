#!/usr/bin/env bash

# test_traffic.sh
# สคริปต์จำลอง Network Traffic สำหรับทดสอบ eBPF TCP Monitor

echo "========================================================"
echo "    TCP Traffic Generator สำหรับทดสอบ Toy Model         "
echo "========================================================"

echo ""
echo "[1/3] กำลังทดสอบ Normal Traffic (เชื่อมต่อ Web ปกติ)..."
echo "คำสั่ง: curl -s https://www.google.com"
curl -s --max-time 3 https://www.google.com > /dev/null
echo "✔ ส่ง Traffic ปกติเรียบร้อย (ดูที่หน้าต่าง tcp_monitor จะเห็น HANDSHAKE OK หรือ CLOSED)"

sleep 2

echo ""
echo "[2/3] กำลังทดสอบอีกหนึ่ง Normal Traffic..."
echo "คำสั่ง: curl -s https://cloudflare.com"
curl -s --max-time 3 https://cloudflare.com > /dev/null
echo "✔ สำเร็จ"

sleep 2

echo ""
echo "[3/3] กำลังทดสอบ Anomaly Traffic (จำลอง SYN Timeout / Retransmission)..."
echo "คำสั่ง: curl ไปยัง IP ที่ไม่ตอบสนอง (Drop packet) เพื่อกระตุ้นให้ Kernel ทำ TCP Retransmit"
# การยิงไปยัง IP ที่ไม่มีตัวตนในเครือข่ายภายนอก จะทำให้ TCP Stack ใน Kernel ส่ง SYN ซ้ำ (Retransmission)
curl -s --connect-timeout 3 http://192.0.2.1:81 > /dev/null 2>&1 || true
echo "✔ ส่ง Anomaly Traffic เรียบร้อย (ดูที่หน้าต่าง tcp_monitor จะเห็น [ANOMALY: RETRANSMISSION])"

echo ""
echo "เสร็จสิ้นการทดสอบ Traffic!"
