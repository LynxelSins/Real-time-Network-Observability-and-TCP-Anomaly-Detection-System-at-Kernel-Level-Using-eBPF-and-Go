// +build ignore

/*
 * tcp_monitor.bpf.c
 * 
 * โปรแกรม eBPF (Kernel Space) สำหรับระบบตรวจสอบสภาวะเครือข่าย TCP
 * 
 * หน้าที่หลัก:
 * 1. ดักจับเหตุการณ์การเปลี่ยนสถานะของ TCP Socket (Tracepoint: sock/inet_sock_set_state)
 * 2. วัดระยะเวลา Handshake Latency และ Connection Lifetime
 * 3. ดักจับการส่ง Packet ซ้ำ (Retransmission) (Tracepoint: tcp/tcp_retransmit_skb)
 * 4. ส่งข้อมูลทั้งหมดขึ้นไปยัง User Space (Go) ผ่าน BPF Ring Buffer
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ประเภทของ Event
#define EVENT_TYPE_STATE_CHANGE 1  // มีการเปลี่ยนสถานะ Socket
#define EVENT_TYPE_RETRANSMIT   2  // มีการส่ง Packet ซ้ำ (TCP Retransmission)

/*
 * โครงสร้างข้อมูล Event ที่จะส่งออกไปยัง User Space ผ่าน BPF Ring Buffer
 * มีการจัดเรียง Memory ให้ได้ 8-byte alignment เพื่อให้ Go อ่านได้ตรงไปตรงมา
 */
struct tcp_event {
    __u64 timestamp_ns;  // เวลาที่เกิด Event (nanoseconds) จาก bpf_ktime_get_ns()
    __u64 duration_ns;   // ระยะเวลา Handshake latency หรือ Connection duration (ns)
    __u8  saddr[4];      // Source IPv4 Address
    __u8  daddr[4];      // Destination IPv4 Address
    __u16 sport;         // Source Port
    __u16 dport;         // Destination Port
    __u16 family;        // Address family (AF_INET = 2)
    __u8  oldstate;      // สถานะก่อนหน้า (TCP state enum)
    __u8  newstate;      // สถานะปัจจุบัน
    __u8  event_type;    // 1: STATE_CHANGE, 2: RETRANSMIT
    __u8  pad[7];        // ช่องว่างสำหรับ padding ให้ครบ 8 bytes
    char  comm[16];      // ชื่อ Process ที่ทำให้เกิด Event (เช่น curl, chrome)
};

// บังคับให้คอมไพเลอร์สร้าง BTF type info สำหรับ struct tcp_event
const struct tcp_event *unused __attribute__((unused));

/*
 * ข้อมูลสำหรับบันทึกเวลาชั่วคราวเพื่อนำมาคำนวณ Duration
 */
struct sock_meta {
    __u64 syn_ts;        // เวลาที่เริ่มส่ง SYN (ใช้คำนวณ Handshake Latency)
    __u64 established_ts;// เวลาที่เชื่อมต่อสำเร็จ (ใช้คำนวณ Connection Duration)
};

/*
 * -------------------------------------------------------------
 * BPF Maps
 * -------------------------------------------------------------
 */

// BPF Ring Buffer: สำหรับส่งข้อมูล Event ออกไปยัง Go User Space แบบ Real-time
// ใช้โครงสร้าง Ring Buffer แทน Perf Buffer เดิมเพื่อประสิทธิภาพที่สูงกว่า
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // บัฟเฟอร์ขนาด 256 KB
} events SEC(".maps");

// BPF Hash Map: สำหรับจำเวลาของ Socket แต่ละตัว โดยใช้ Socket pointer (skaddr) เป็น Key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, const void *);
    __type(value, struct sock_meta);
} sock_store SEC(".maps");


/*
 * -------------------------------------------------------------
 * Tracepoint 1: sock/inet_sock_set_state
 * ดักจับทุกครั้งที่ TCP Socket เปลี่ยนสถานะ
 * -------------------------------------------------------------
 */
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // เราสนใจเฉพาะ IPv4 ใน Toy Model นี้เพื่อความเข้าใจง่าย (AF_INET == 2)
    if (ctx->family != 2) {
        return 0;
    }

    const void *sk = ctx->skaddr;
    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;
    __u64 now = bpf_ktime_get_ns();
    __u64 duration = 0;

    // 1. ถ้าเริ่มส่ง SYN (TCP_SYN_SENT หรือ TCP_SYN_RECV): บันทึกเวลาเริ่มต้นไว้ใน Map
    if (newstate == TCP_SYN_SENT || newstate == TCP_SYN_RECV) {
        struct sock_meta meta = {};
        meta.syn_ts = now;
        bpf_map_update_elem(&sock_store, &sk, &meta, BPF_ANY);
    }
    // 2. ถ้าเชื่อมต่อสำเร็จ (TCP_ESTABLISHED): คำนวณ Handshake Latency (SYN -> ESTABLISHED)
    else if (newstate == TCP_ESTABLISHED) {
        struct sock_meta *meta = bpf_map_lookup_elem(&sock_store, &sk);
        if (meta && meta->syn_ts > 0) {
            duration = now - meta->syn_ts;
            meta->established_ts = now; // บันทึกเวลาเริ่มต้นของ connection
        }
    }
    // 3. ถ้าปิดการเชื่อมต่อ (TCP_CLOSE): คำนวณอายุของ Connection และลบข้อมูลออกจาก Map เพื่อคืนหน่วยความจำ
    else if (newstate == TCP_CLOSE) {
        struct sock_meta *meta = bpf_map_lookup_elem(&sock_store, &sk);
        if (meta) {
            if (meta->established_ts > 0) {
                duration = now - meta->established_ts;
            } else if (meta->syn_ts > 0) {
                duration = now - meta->syn_ts;
            }
            bpf_map_delete_elem(&sock_store, &sk);
        }
    }

    // จองพื้นที่ใน Ring Buffer เพื่อเขียนข้อมูล Event
    struct tcp_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // หาก Buffer เต็ม Event นี้จะถูก drop
        return 0;
    }

    // เติมข้อมูลลงใน Struct Event
    event->timestamp_ns = now;
    event->duration_ns = duration;
    event->sport = ctx->sport;
    event->dport = ctx->dport;
    event->family = ctx->family;
    event->oldstate = (__u8)oldstate;
    event->newstate = (__u8)newstate;
    event->event_type = EVENT_TYPE_STATE_CHANGE;

    // คัดลอก IP Address (IPv4 4 bytes)
    __builtin_memcpy(event->saddr, ctx->saddr, 4);
    __builtin_memcpy(event->daddr, ctx->daddr, 4);

    // ดึงชื่อ Process ที่ทำให้เกิดเหตุการณ์
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // ส่ง Event ขึ้นไปยัง User Space
    bpf_ringbuf_submit(event, 0);

    return 0;
}


/*
 * -------------------------------------------------------------
 * Tracepoint 2: tcp/tcp_retransmit_skb
 * ดักจับเหตุการณ์เมื่อมีการส่ง TCP Segment ซ้ำ (Retransmission)
 * ตัวบ่งชี้ความผิดปกติของเครือข่าย เช่น แพ็กเก็ตตกหล่น หรือ Latency พุ่งสูง
 * -------------------------------------------------------------
 */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_event_raw_tcp_retransmit_skb *ctx)
{
    // สนใจเฉพาะ IPv4
    if (ctx->family != 2) {
        return 0;
    }

    struct tcp_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->duration_ns = 0;
    event->sport = ctx->sport;
    event->dport = ctx->dport;
    event->family = ctx->family;
    event->oldstate = (__u8)ctx->state;
    event->newstate = (__u8)ctx->state;
    event->event_type = EVENT_TYPE_RETRANSMIT;

    __builtin_memcpy(event->saddr, ctx->saddr, 4);
    __builtin_memcpy(event->daddr, ctx->daddr, 4);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}
