# BrickGuard

BrickGuard 是从 KPMDynaLab 的 BLG（Boot Lifeguard）代码独立出来的
KernelPatch KPM 项目。仓库只保留两类能力：

1. 对 Linux 块设备文件入口的写入保护；
2. BLG Recovery Pack、内核只读 RAM Cache、恢复映射和 loop 自测。

它不包含 DynaLab 的进程跟踪、认证会话、文件事件、重启 Hook 或分析
Profile，也没有 fastboot/EDL/recovery 刷写器。

## 三种模式

KPM 加载参数必须是单个字符：

| 参数 | 模式 | 行为 |
| --- | --- | --- |
| 0 | OFF | 放行块设备操作；允许准备、验证和释放 BLG Cache |
| 1 | DENY | 拦截覆盖范围内的操作并返回 -EPERM |
| 2 | SIMULATE | 丢弃普通写入并返回成功；discard/fallocate/uring 返回成功 |

模式 2 无法安全伪造一个可写共享 mmap，所以新的 writable shared mmap
会返回 -EOPNOTSUPP，不会让真实写入穿透。

模式由 KernelPatch 加载参数或受信任的 KPM CTL0 修改。procfs 控制面
不提供模式切换命令。支持的 CTL0 payload：

~~~text
STATUS
BLG STATUS
MODE 0
MODE 1
MODE 2
~~~

也接受裸参数 0、1、2。

模式切换带有在途 I/O 屏障：CTL0 返回前，已经按旧模式进入 Hook 的调用
必须结束；切换窗口中新进入的受保护操作会被拒绝。

## 拦截方式

这不是路径字符串匹配。BrickGuard Hook 的是块设备 file operations，
因此 /dev/block/x、//dev/block/x、by-name symlink 或另建的同一设备
节点，只要最终进入同一个块设备函数，行为相同。

当前 Hook：

- blkdev_write_iter
- blkdev_ioctl
- compat_blkdev_ioctl（目标内核存在时）
- blkdev_fallocate
- blkdev_mmap
- blkdev_uring_cmd（目标内核存在时）

ioctl 范围为 BLKZEROOUT、BLKDISCARD、BLKSECDISCARD。Linux 6.12
中的 block uring command 当前是 discard，因此整个入口可按模式处理。

以下不在这个 KPM 的保证范围内：

- 切换保护模式前已经建立的 writable mmap；
- mounted filesystem 产生的正常 writeback BIO；
- 内核代码直接调用 submit_bio；
- 厂商私有 ioctl、SG/BSG、MTD 或其他字符设备写入路径；
- 模块尚未加载或已经卸载的时间窗口；
- bootloader fastboot、EDL、独立 recovery 或外部编程器。

因此这里的“全局”指所有进程访问上述 raw block file-operation 入口，
不是覆盖设备从 boot ROM 到 Android 的所有写入来源。

## BLG 数据链

brickguard setup 完成下面的设备本地流程：

1. 读取旧 BLG 已支持的 Qualcomm boot-chain 分区候选；
2. 生成严格的 Pack v3 device.txt 和 SHA-256 manifest，并对内容相同的
   A/B 镜像做 hardlink 去重；
3. 拒绝未知根目录项、非法镜像名、外部 hardlink 和非 v3 元数据，在已
   打开的文件描述符上重新计算每个文件的 SHA-256；
4. 对规范 manifest 计算 pack_id；
5. 严格顺序上传到最大 256 MiB 的 vmalloc Cache；
6. 在内核中计算 SHA-256，并把 Cache 页面设为 RO；
7. 从只读 Cache 回读并逐镜像比较 digest，再复核内核 digest；
8. 将 active-slot 镜像映射到 inactive-slot target；
9. 将共享 EFISP 映射回自身，只保存恢复计划，不写真实分区。

Cache、map 和磁盘 Pack 通过同一个 pack_id 绑定。重建 Pack 后，旧
Cache/map 不会被 verify 或 selftest 当成同一份数据。
prepare、verify 和 selftest 还会比较 Pack 中的 product/hardware 与当前
Android 设备；异机 Pack 不能进入数据链。

旧 BLG 的独立 EFISP 常驻模拟策略已并入统一模式：模式 0 对 EFISP 也真实
放行，模式 1 拒绝，模式 2 模拟成功。这样保持用户指定的“0=关闭拦截”。

`pack_id` 是本地完整性与同源绑定标识，不是数字签名或设备证明。拥有 root
且能修改整个 Pack 的主体仍可重建 manifest 和新的 pack_id。

brickguard selftest 只把计划写入临时 regular-file-backed loop 设备，
注入一个确定的字节错误，然后检测、修复并再次从后端验证。KPM 会校验
loop major、sysfs backing path 和普通文件大小。项目没有面向真实分区
执行恢复写入的命令。

## 构建

主机测试：

~~~sh
make test
make sanitize
~~~

静态 ARM64 CLI：

~~~sh
make cli
~~~

KPM 必须使用与设备完全匹配并已 prepare 的 Android 内核源码：

~~~sh
make kpm KDIR=/path/to/prepared/android-kernel
~~~

此外必须先给用于目标 boot 镜像的 KernelPatch 源码应用
`kernelpatch/0001-kpm-honor-exit-veto.patch` 并重新构建/打补丁。BrickGuard
引用补丁导出的握手符号；未修改的 loader 会在任何 Hook 安装前拒绝 KPM。
原因和应用要求见 [KernelPatch 集成](docs/KERNELPATCH.md)。

产物：

~~~text
build/brickguard-arm64
build/BrickGuard-0.1.0-arm64.kpm
~~~

KPM 编译固定使用 -mno-outline-atomics，防止生成加载器无法解析的
__aarch64_cas 等 libgcc 符号。

## 设备流程

启动后先卸载旧 KPMDynaLab 或任何采用不兼容卸载方式的同类 KPM，再加载
BrickGuard。推荐顺序：

~~~text
1. 以参数 0 加载 BrickGuard
2. brickguard setup
3. brickguard verify
4. brickguard selftest
5. 通过 KernelPatch Manager CTL0 切换到 MODE 1 或 MODE 2
~~~

CLI 示例：

~~~sh
brickguard status
brickguard pack create
brickguard pack verify
brickguard prepare
brickguard verify
brickguard selftest
brickguard release
~~~

准备、释放和 selftest 仅允许在模式 0 执行。模式 2 会让调用方相信数据
已写入，但实际数据未改变，可能使调用方自身状态不一致，只应用于明确
需要“模拟成功”的场景。

BrickGuard 加载成功后是 pinned KPM：运行期卸载始终返回 -EBUSY，更新或
移除必须重启。初始化若在必需 Hook 已部分安装后失败，会固定到模式 1 并
报告 `DEGRADED ... REBOOT REQUIRED`，不会释放仍被 Hook 引用的代码。
不要与 Hook 相同 blkdev 符号、且会改写同一 fargs 返回状态的未知 KPM 共存；
链上回调的先后顺序会影响最终的 skip/ret，必须逐个做兼容性审计。

详细协议和测试步骤见 [协议](docs/PROTOCOL.md)、
[KernelPatch 集成](docs/KERNELPATCH.md) 与 [设备测试](docs/DEVICE_TEST.md)。

## 许可证

本项目采用 GPL-2.0-only。KPM 直接使用并链接 KernelPatch 提供的 GPL v2
Hook/loader ABI，选择 GPL v2 only 可以与上游许可证保持明确兼容，而不
额外声明 GPL v3 条款。
