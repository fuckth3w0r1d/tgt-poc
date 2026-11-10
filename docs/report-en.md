# tgt (tgtd) iSCSI Data-Out out-of-bounds write and R2T address leak

## Overview

The iSCSI front end of `tgt` (Linux SCSI target framework, daemon `tgtd`) has two defects that need no credentials. Together they give code execution in the `tgtd` process from any host that can reach port 3260. `tgtd` runs as `root`, so the executed command runs as `root`.

| Defect | Location | Effect |
| --- | --- | --- |
| Data-Out has no bounds check | `usr/iscsi/iscsid.c:1578` | Arbitrary offset write relative to the command data buffer, up to 16 MiB, fully controlled |
| R2T leaks a heap address | `usr/iscsi/iscsid.c:1181` | Low 32 bits of a `struct iscsi_task` pointer, one per WRITE command |

Both sit on the post-login SCSI command path, ahead of CHAP authentication.

## Root cause

### Data-Out has no bounds check

From `usr/iscsi/iscsid.c:1561`, `iscsi_data_out_rx_start()` finds the command by ITT and then computes the receive buffer directly:

```c
list_for_each_entry(task, &conn->session->cmd_list, c_hlist) {
	if (task->tag == req->itt)
		goto found;
}
return -EINVAL;
found:
	...
	conn->req.data = task->data + be32_to_cpu(req->offset);   /* iscsid.c:1578 */

	task->offset += ntoh24(req->dlength);
	task->r2t_count -= ntoh24(req->dlength);

	conn->rx_task = task;
```

`conn->req.data` is handed to the transport as the destination of `read()`:

```c
ret = conn->tp->ep_read(conn, conn->rx_buffer, conn->rx_size);
```

All three inputs come from the initiator:

| Field | Source | Range |
| --- | --- | --- |
| `req->offset` | Data-Out BHS bytes 40..43 | full 32 bits |
| `req->dlength` | Data-Out BHS bytes 5..7 | 24 bits, up to 16 MiB |
| payload | PDU data segment | fully controlled |

Neither `offset` nor `dlength` is compared against the command data buffer, and the sum is not checked for overflow. When a command has no data buffer `task->data` is `NULL`, and that case is not rejected either, so the Data-Out writes to `NULL + offset`.

### R2T leaks a heap address

From `usr/iscsi/iscsid.c:1161`, `iscsi_r2t_build()` fills the response with:

```c
rsp->itt = task->req.itt;
...
rsp->ttt = (unsigned long) task;                              /* iscsid.c:1181 */
```

`TTT` is a 32-bit PDU field, so the assignment truncates and the initiator receives the low 32 bits of the `struct iscsi_task` address. RFC 7143 makes the TTT opaque to the initiator, and `tgtd` looks the task up by ITT on Data-Out rather than by TTT.

### Trigger path

```text
TCP handshake + two-stage login (SecurityNegotiation / OperationalNegotiation)
  -> SCSI_CMD (WRITE_10, data_length = 2048)
    -> iscsi_scsi_cmd_rx_start -> iscsi_alloc_task
      -> iscsi_r2t_build                 rsp->ttt = (unsigned long)task   [leak]
  -> SCSI_DATA_OUT (itt = that command, arbitrary offset / dlength / payload)
    -> iscsi_data_out_rx_start
      -> conn->req.data = task->data + offset                            [no check]
        -> do_recv -> conn->tp->ep_read -> read(fd, conn->req.data, ...)  [OOB write]
```

Once a command with a data length enters the R2T state, Data-Out can be sent against it; the trigger does not depend on command semantics.

## Affected versions

Upstream `fujita/tgt` `v1.0.97` and earlier are affected; `v1.0.98` fixes it. The fix commits `e3b418a` (record `task->len` and reject out-of-range Data-Out) and `a3f4a25` (set `rsp->ttt` to 0) are both contained only in `v1.0.98`. Neither carries a CVE or a `Reported-by`.

Checked against the distribution package indexes on 2026-11-08; the following still ship a pre-fix source tree:

| Distribution | Release | Package version | Status |
| --- | --- | --- | --- |
| Debian | 12 bookworm | `tgt 1:1.0.85-1+deb12u1` | Affected |
| Debian | 13 trixie | `tgt 1:1.0.85-1.3` | Affected |
| Debian | forky / sid | `tgt 1:1.0.85-1.3` | Affected |
| Ubuntu | 20.04 focal | `tgt 1:1.0.79-2ubuntu1.1` | Affected |
| Ubuntu | 22.04 jammy | `tgt 1:1.0.80-1ubuntu2` | Affected |
| Ubuntu | 24.04 noble | `tgt 1:1.0.85-1.1ubuntu6` | Affected |
| Ubuntu | 25.10 / 26.04 / devel | `tgt 1:1.0.85-1.3ubuntu2` | Affected |
| Fedora | 43 / 44 / 45 | `scsi-target-utils 1.0.97-7` | Affected |
| Fedora | 43 / 44 / 45 updates-testing | `scsi-target-utils 1.0.98-1` | Fixed, pending push to stable |
| Fedora | Rawhide | `scsi-target-utils 1.0.98-1.fc46` | Fixed |
| EPEL | 10.2 / 10.3 / 10.4 | `scsi-target-utils 1.0.97-5` | Affected |

The chain was verified end to end on Debian 12 `1:1.0.85-1+deb12u1` and Debian 13 `1:1.0.85-1.3`; the other rows are judged from source.

## Exploit analysis

### Primitives

- **Relative write**: up to 16 MiB of controlled bytes at `task->data + offset`, with `offset` a 32-bit unsigned value relative to that command's own data buffer.
- **Heap address leak**: low 32 bits of a `task` pointer, one per WRITE command.
- **Field rewrite between tasks**: every field of `struct iscsi_task` lives in the same heap region at a fixed relative position, so the relative write can rewrite fields of one task through another.

### Protections in the target binary

Both archive `tgtd` binaries are `Type: DYN` (PIE) with `FLAGS: BIND_NOW` and `FLAGS_1: NOW PIE`, and `GNU_RELRO` covers the GOT, so the GOT is read-only. The binary imports `execv` but not `system`, `popen` or `execl`, and it has no stack pivot gadget such as `mov rsp, rdi` or `leave; ret`.

The chain therefore lands on a writable function pointer table: `struct iscsi_transport iscsi_tcp` lives in `.data` (bookworm `0x585C0`, trixie `0x595C0`), outside the `GNU_RELRO` range, and is writable at runtime. Its `free_data_buf` slot is at `+0xa0`.

### Chain

1. **Obtain task addresses.** After login, send 28 WRITE_10 commands with `data_length = 2048`. Each one produces an R2T whose `ttt` yields the low 32 bits of that task pointer, so the relative positions of all 28 tasks are known. Tasks on one connection are packed 688 bytes apart (`sizeof(struct iscsi_task)`), five per group.
2. **Determine the data buffer base.** `task->data` comes from `posix_memalign(4 KiB)`, so it is page aligned and sits a few pages above the lowest task address. The candidates `(los[0] & ~0xFFF) + 0x1000/0x2000/0x3000` are tried in turn; a steering command that only produces `SCSI_CMD_RSP` when the write happened tells which one is right.
3. **Leak PIE and the heap high bits.** Set one task's CDB LBA to 8, clear its `r2t_count`, point its `task->data` at the heap `scsi_lu` chunk (`los[0] - 45952` on bookworm, `los[0] - 43088` on trixie), then let that WRITE run. `tgtd` `pwrite()`s the chunk to LBA 8 and frees it afterwards, so the daemon keeps running. On a fresh connection, READ_10 of LBA 8 returns a pointer inside the PIE image at `lu + 0x80` (bookworm `pie + 0x3B670`, trixie `pie + 0x3C540`), and the same chunk holds a heap pointer that supplies the heap high bits.
4. **Rewrite the transport table.** Use the relative write to set `iscsi_tcp.free_data_buf` (`pie + ISCSI_TCP + 0xa0`) to `execv@plt` (`0x130D0` on both bookworm and trixie).
5. **Stage the fake structures.** In the data buffer, lay out a fake `struct iscsi_connection` starting with `"/bin/sh\0"`, with `+0x268` (the real `conn->tp` offset) pointing at the genuine `&iscsi_tcp`, and an `argv = { "/bin/sh", "-c", <command>, NULL }` vector at `+0x400`.
6. **Trigger.** Point one task's `conn` (`+104`) at the fake connection, its `scmd.in_sdb.buffer` (`+280`) at `argv`, clear `flags` (`+160`) and `scmd.c_target` (`+208`), and set the real connection's `tx_task` (`+536`) to that task. Closing the socket makes `conn_close()` take the `tx_task` branch (`usr/iscsi/conn.c:126-131`, which has no `task->conn != conn` filter) and call `iscsi_free_task()`:

```c
conn->tp->free_data_buf(conn, scsi_get_in_buffer(&task->scmd));   /* iscsid.c:1227 */
```

which compiles to `mov 0x268(%rbp),%rax; mov 0x118(%rbx),%rsi; mov %rbp,%rdi; call *0xa0(%rax)`, i.e. `execv(fake_conn, argv)` with `fake_conn` starting with `"/bin/sh\0"`.

### Payload constants

| Constant | bookworm `1:1.0.85-1+deb12u1` | trixie `1:1.0.85-1.3` |
| --- | --- | --- |
| `LU_DELTA` (`scsi_lu` relative to `los[0]`) | `-45952` | `-43088` |
| `ISCSI_TCP` (`&iscsi_tcp`) | `0x585C0` | `0x595C0` |
| `PIE_PTR_BIAS` (pointer at `lu + 0x80`) | `0x3B670` | `0x3C540` |
| `EXECV_PLT` | `0x130D0` | `0x130D0` |

The remaining offsets come from the layout of `struct iscsi_task` and `struct iscsi_connection`, which is identical in both packages: `r2t_count` +180, `data` +200, `conn` +104, `scmd.in_sdb.buffer` +280, `scmd.out_sdb.buffer` +304, `flags` +160, `scmd.c_target` +208, `conn->tp` +616, `conn->tx_task` +536.
