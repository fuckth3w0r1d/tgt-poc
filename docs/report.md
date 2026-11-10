# tgt (tgtd) iSCSI Data-Out 越界写与 R2T 地址泄露

## 概述

`tgt`（Linux SCSI target framework，守护进程 `tgtd`）的 iSCSI 前端有两处未认证即可触发的问题，组合后可从任意能连上 3260 端口的主机取得 `tgtd` 进程的代码执行权限。`tgtd` 以 `root` 运行，被执行的命令同样是 `root`。

| 缺陷 | 位置 | 效果 |
| --- | --- | --- |
| Data-Out 缺少边界检查 | `usr/iscsi/iscsid.c:1578` | 相对命令数据缓冲区的任意偏移写，最多 16 MiB，内容完全可控 |
| R2T 泄露堆地址 | `usr/iscsi/iscsid.c:1181` | 每条 WRITE 命令泄露 `struct iscsi_task` 指针低 32 位 |

两者都在登录后的 SCSI 命令路径上，位于 CHAP 认证之前。

## 漏洞成因

### Data-Out 缺少边界检查

`usr/iscsi/iscsid.c:1561` 起，`iscsi_data_out_rx_start()` 按 ITT 找到对应命令后直接计算接收缓冲区：

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

`conn->req.data` 随后被 `do_recv()` 作为 `read()` 的目标缓冲区交给传输层：

```c
ret = conn->tp->ep_read(conn, conn->rx_buffer, conn->rx_size);
```

三处输入全部由发起方决定：

| 字段 | 来源 | 取值范围 |
| --- | --- | --- |
| `req->offset` | Data-Out BHS 字节 40..43 | 完整 32 位 |
| `req->dlength` | Data-Out BHS 字节 5..7 | 24 位，最大 16 MiB |
| payload | PDU 数据段 | 完全可控 |

`offset` 与 `dlength` 都不与命令的数据缓冲区长度比较，二者相加也不做溢出检查。命令没有数据缓冲区时 `task->data` 为 `NULL`，这种情况同样不被拦截，Data-Out 就写到 `NULL + offset`。

### R2T 泄露堆地址

`usr/iscsi/iscsid.c:1161` 起，`iscsi_r2t_build()` 构造 R2T 响应时写入：

```c
rsp->itt = task->req.itt;
...
rsp->ttt = (unsigned long) task;                              /* iscsid.c:1181 */
```

`TTT` 在 PDU 中只有 32 位，赋值时被截断，发起方因此拿到 `struct iscsi_task` 地址的低 32 位。RFC 7143 规定 TTT 对发起方不透明，`tgtd` 在 Data-Out 上按 ITT 查找任务，从不使用 TTT。

### 触发路径

```text
TCP 握手 + 两段 iSCSI 登录 (SecurityNegotiation / OperationalNegotiation)
  -> SCSI_CMD (WRITE_10, data_length = 2048)
    -> iscsi_scsi_cmd_rx_start -> iscsi_alloc_task
      -> iscsi_r2t_build                 rsp->ttt = (unsigned long)task   [泄露]
  -> SCSI_DATA_OUT (itt = 该命令, offset / dlength / 内容任意)
    -> iscsi_data_out_rx_start
      -> conn->req.data = task->data + offset                            [无检查]
        -> do_recv -> conn->tp->ep_read -> read(fd, conn->req.data, ...)  [越界写]
```

一条带数据长度的命令进入 R2T 状态后就能收到 Data-Out，触发不依赖命令语义。

## 危害影响版本

上游 `fujita/tgt` 的 `v1.0.97` 及更早版本受影响，`v1.0.98` 修复。修复提交 `e3b418a`（记录 `task->len` 并拒绝越界 Data-Out）与 `a3f4a25`（`rsp->ttt` 置 0）的 `git tag --contains` 都只包含 `v1.0.98`，两者都没有 CVE 编号，也没有 `Reported-by`。

已核对发行版包索引（2026-11-08），以下版本仍基于修复前的源码：

| 发行版 | 版本 | 包版本 | 状态 |
| --- | --- | --- | --- |
| Debian | 12 bookworm | `tgt 1:1.0.85-1+deb12u1` | 受影响 |
| Debian | 13 trixie | `tgt 1:1.0.85-1.3` | 受影响 |
| Debian | forky / sid | `tgt 1:1.0.85-1.3` | 受影响 |
| Ubuntu | 20.04 focal | `tgt 1:1.0.79-2ubuntu1.1` | 受影响 |
| Ubuntu | 22.04 jammy | `tgt 1:1.0.80-1ubuntu2` | 受影响 |
| Ubuntu | 24.04 noble | `tgt 1:1.0.85-1.1ubuntu6` | 受影响 |
| Ubuntu | 25.10 / 26.04 / devel | `tgt 1:1.0.85-1.3ubuntu2` | 受影响 |
| Fedora | 43 / 44 / 45 | `scsi-target-utils 1.0.97-7` | 受影响 |
| Fedora | 43 / 44 / 45 updates-testing | `scsi-target-utils 1.0.98-1` | 已修，待推稳定版 |
| Fedora | Rawhide | `scsi-target-utils 1.0.98-1.fc46` | 已修 |
| EPEL | 10.2 / 10.3 / 10.4 | `scsi-target-utils 1.0.97-5` | 受影响 |

Debian 12 `1:1.0.85-1+deb12u1` 与 Debian 13 `1:1.0.85-1.3` 上完成了端到端验证，其余按源码判断。

## 利用分析

### 原语

- **相对写**：向 `task->data + offset` 写入最多 16 MiB 可控字节，`offset` 为 32 位无符号数，基准是这条命令自己的数据缓冲区。
- **堆地址泄露**：每条 WRITE 命令给出一个 `task` 指针的低 32 位。
- **任务间字段改写**：`struct iscsi_task` 的字段都在同一个堆区且相对位置固定，可以用相对写在任务之间互相改写字段。

### 目标二进制的防护

两个官方包的 `tgtd` 都是 `Type: DYN`（PIE）、`FLAGS: BIND_NOW`、`FLAGS_1: NOW PIE`，`GNU_RELRO` 覆盖 GOT，GOT 不可写。二进制只导入 `execv`，没有 `system`/`popen`/`execl`，也没有 `mov rsp, rdi`、`leave; ret` 这类栈迁移 gadget。

因此链上的落点选在可写的函数指针表：`struct iscsi_transport iscsi_tcp` 位于 `.data`（bookworm `0x585C0`，trixie `0x595C0`），在 `GNU_RELRO` 范围之外，运行时可写，其 `free_data_buf` 槽在 `+0xa0`。

### 利用链

1. **取任务地址**：登录后连发 28 条 WRITE_10（`data_length = 2048`），每条命令回一个 R2T，其 `ttt` 给出该任务指针低 32 位。28 个任务的相对位置由此已知；同一连接内的任务按 688 字节（`sizeof(struct iscsi_task)`）紧密相邻，每 5 个一组。
2. **确定数据缓冲区基址**：`task->data` 由 `posix_memalign(4 KiB)` 分配，页对齐，位于最低任务地址之上若干页。候选基址 `(los[0] & ~0xFFF) + 0x1000/0x2000/0x3000` 逐个尝试，判定依据是引导命令是否收到 `SCSI_CMD_RSP`。
3. **泄露 PIE 与堆高位**：把某条任务的 CDB LBA 改成 8、`r2t_count` 清零、`task->data` 指向堆上的 `scsi_lu`（bookworm `los[0] - 45952`，trixie `los[0] - 43088`），让这条 WRITE 执行。`tgtd` 把这块堆内存 `pwrite()` 到 LBA 8 并在完成后释放，进程继续运行。换一条新连接用 READ_10 读回 LBA 8，在 `lu + 0x80` 处得到落在 PIE 内的指针（bookworm `pie + 0x3B670`，trixie `pie + 0x3C540`），同一块里还有堆指针，给出堆高位。
4. **改写传输表**：用相对写把 `iscsi_tcp.free_data_buf`（`pie + ISCSI_TCP + 0xa0`）改成 `execv@plt`（bookworm 与 trixie 都是 `0x130D0`）。
5. **布置伪造结构**：在数据缓冲区里布置以 `"/bin/sh\0"` 开头的伪造 `struct iscsi_connection`，其 `+0x268`（真正的 `conn->tp` 偏移）指向真实的 `&iscsi_tcp`，`+0x400` 处布置 `argv = { "/bin/sh", "-c", <命令>, NULL }`。
6. **触发**：把某条任务的 `conn`（`+104`）指向伪造连接、`scmd.in_sdb.buffer`（`+280`）指向 `argv`、`flags`（`+160`）与 `scmd.c_target`（`+208`）清零，并把真实连接的 `tx_task`（`+536`）设为这条任务。断开 socket 后 `conn_close()` 走 `tx_task` 分支（`usr/iscsi/conn.c:126-131`，该分支没有 `task->conn != conn` 的过滤），调用 `iscsi_free_task()`：

```c
conn->tp->free_data_buf(conn, scsi_get_in_buffer(&task->scmd));   /* iscsid.c:1227 */
```

编译后是 `mov 0x268(%rbp),%rax; mov 0x118(%rbx),%rsi; mov %rbp,%rdi; call *0xa0(%rax)`，即 `execv(fake_conn, argv)`，而 `fake_conn` 的首字节是 `"/bin/sh\0"`。

### 载荷常量

| 常量 | bookworm `1:1.0.85-1+deb12u1` | trixie `1:1.0.85-1.3` |
| --- | --- | --- |
| `LU_DELTA`（`scsi_lu` 相对 `los[0]`） | `-45952` | `-43088` |
| `ISCSI_TCP`（`&iscsi_tcp`） | `0x585C0` | `0x595C0` |
| `PIE_PTR_BIAS`（`lu + 0x80` 处的指针） | `0x3B670` | `0x3C540` |
| `EXECV_PLT` | `0x130D0` | `0x130D0` |

其余偏移来自 `struct iscsi_task` 与 `struct iscsi_connection` 的布局，两个包相同：`r2t_count` +180、`data` +200、`conn` +104、`scmd.in_sdb.buffer` +280、`scmd.out_sdb.buffer` +304、`flags` +160、`scmd.c_target` +208、`conn->tp` +616、`conn->tx_task` +536。
