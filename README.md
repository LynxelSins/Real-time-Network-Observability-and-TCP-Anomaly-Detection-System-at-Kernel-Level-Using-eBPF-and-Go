# eBPF TCP Network Monitor & Anomaly Detection (Toy Model PoC)

ระบบต้นแบบตรวจสอบสภาวะเครือข่าย TCP แบบเรียลไทม์ และตรวจจับสิ่งผิดปกติในระดับเคอร์เนลด้วย eBPF และภาษา Go ตามกรอบข้อเสนอโครงการใน `ebpf_tcp_presentation.md`

## 📁 โครงสร้างโปรเจกต์

```text
eBPFproject/
├── bpf/
│   ├── vmlinux.h               # BTF type information ของ Kernel (สร้างโดย bpftool)
│   └── tcp_monitor.bpf.c       # โค้ด eBPF (Kernel Space) ดักจับ TCP events และส่งเข้า RingBuffer
├── bpf_bpfel.go / bpf_bpfeb.go # Go bindings และ BPF bytecode ที่สร้างจาก bpf2go
├── gen.go                      # สคริปต์คำสั่ง go:generate เรียก bpf2go
├── main.go                     # โค้ด Go (User Space) อ่าน RingBuffer และทำ Anomaly Detection
├── tcp_monitor                 # Executable binary ที่คอมไพล์สำเร็จแล้ว
└── test_traffic.sh             # สคริปต์ยิง Traffic จำลองสำหรับทดสอบระบบ
```

## ⚙️ วิธีการคอมไพล์ใหม่ (เมื่อมีการแก้ไขโค้ด)

ถ้ามีการแก้ไขโค้ดใน `bpf/tcp_monitor.bpf.c`:
```bash
go generate ./...
go build -o tcp_monitor .
```

## 🚀 วิธีการรันใช้งาน

เนื่องจากโปรแกรม eBPF จำเป็นต้องโหลดเข้า Kernel Space จึงต้องใช้สิทธิ์ root (`sudo`):

```bash
sudo ./tcp_monitor
```

## 🧪 วิธีการทดสอบ (เปิดอีก Terminal หนึ่ง)

เปิดอีกหน้าต่าง Terminal หนึ่งแล้วรัน:
```bash
./test_traffic.sh
```
หรือทดสอบด้วยคำสั่งทั่วไป เช่น:
- เปิดเว็บหรือ `curl https://google.com` (เพื่อดู Normal Handshake & Close)
- `curl --connect-timeout 2 http://192.0.2.1:81` (เพื่อทดสอบ Anomaly Retransmission)
