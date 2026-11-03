# ClusterMAX

<div align="center">

[English](README.md) | **中文**

</div>

本仓库包含 `cmax` 命令行工具，我们在开展 ClusterMAX 研究时使用它来审计 GPU 集群和独立机器。

首次发布的版本仅包含完整测试套件中的一小部分，用于配合我们在 ClusterMAX 3.0 发布前推出的 GPU 云服务安全相关文章。

此版本的 `cmax` CLI 提供以下命令：

| 命令 | 功能 |
|---|---|
| `cmax audit security` | 执行专项只读安全审计。 |
| `cmax audit` | 执行完整集群审计，范围不限于安全。 |
| `cmax audit review` | 查看已保存的审计输出，不运行新的检查。 |

## 安装 ClusterMAX

[安全版本发布准备清单](docs/security-release-preparation.md)介绍了新增检查和发布条件。PR 验证不会发布稳定版软件包。

稳定版通过手动触发并经批准的工作流发布。该工作流先验证 PyPI 上传结果，再基于同一提交和同一组构建产物创建对应的 GitHub 标签和 Release。每夜构建版不会创建 GitHub Release。

ClusterMAX 需要 Python 3.10 或更新版本。安装当前版本：
```
uv venv
source .venv/bin/activate
uv pip install clustermax
cmax -v
```

也可以使用 `--pre` 选项安装最新的每夜构建版：
```
uv pip install --pre -U clustermax
```

使用 CLI 时，可通过 `-h` 查看可用选项：
```
cmax -h
cmax audit -h
cmax audit security -h
```

已准备的稳定版为 `0.3.0`。后续每夜构建版采用 `0.3.1.devYYYYMMDDNN` 格式，启用 `--pre` 时，其版本顺序高于 `0.3.0`。本分支中的版本号变更不会发布任何一个渠道的版本。

## 公开文档

[ClusterMAX 网站](https://clustermax.semianalysis.com/)介绍了评级体系。[评估标准](https://www.clustermax.ai/criteria)列出了完整检查清单，[预期要求页面](https://www.clustermax.ai/expectations)则列出了我们对 Slurm、Kubernetes、独立机器、监控面板和健康检查的明确要求。

## 运行安全审计

当前的[最低版本表](https://www.clustermax.ai/minimum-versions)列出了评级所用的软件和固件版本，每个版本值均附有厂商安全公告。`cmax audit security` 启动时会获取该表的[机器可读版本](https://semianalysisai.github.io/ClusterMAX/minimum-versions.json)（可通过 `--no-fetch-minimums` 跳过）。`minimum-versions-publish` 工作流将这一个文件部署到本仓库的 GitHub Pages 站点。成功刷新后，`refreshed` 时间戳每天更新；`changed` 时间戳则仅在最低版本值发生变化时更新。CLI 将最近获取的表保存在 `~/.cache/clustermax/` 中，因此离线运行时会使用该副本进行评级，而非软件包内较旧的表。如果获取失败，且正在使用的表距上次刷新已超过 7 天，审计会发出警告。

只读的 Bad Epoll 检查 `security.badEpoll.status` 根据 [CVE-2026-46242](https://ubuntu.com/security/CVE-2026-46242) 检查正在运行的内核。它覆盖 Ubuntu 24.04 GA 6.8 generic、Ubuntu 22.04 HWE 6.8 generic、Ubuntu 24.04 NVIDIA 6.17（`nvidia` 和 `nvidia-64k`）以及 Ubuntu 26.04 GA 7.0 generic 软件包。每个源码包都有各自的最低修复版本。检查要求正在运行的内核签名与已安装软件包的证据相匹配。即使已安装更新的内核，只要尚未运行该内核，失败结果就不会消除。不支持的内核变体、缺失的证据，以及已启用或无法读取的 livepatch 状态，都会产生未知结果，需要由服务商提供补丁证据。该检查不会运行漏洞利用程序，也不能证明服务商内核的真实性。如果显式固定使用的最低版本表缺少相应映射，结果为未知。

安全信息采集会区分被抽样工作节点上的宿主机、GPU Operator 容器和正在运行的 GPU 工作负载。当 `nvidia-smi` 不在宿主机的命令搜索路径中时，驱动检测可以读取已加载的内核模块。Toolkit 检测还会检查 GPU Operator 安装目录。CUDA Toolkit 版本取自 `nvcc` 或 Toolkit 元数据，不使用驱动所标示的 CUDA 兼容版本或镜像标签。

网络探测会优先使用经过验证的特权宿主机根目录挂载（如果可用）。缺少 `lspci` 时，它可以通过 sysfs 枚举 PCI 设备。它使用只读的 `mlxconfig -e` 查询，并且仅根据 Current 列评级。默认值和下次启动设置不能证明当前已实现隔离。它不会安装工具或启动 `mst`。权限不足、扫描不完整以及未经评估的固件版本分支均保持未知状态。仅完成拓扑扫描不能证明对物理 NVLink 域的独占所有权。

被标记为保留（hold）的已安装内核也会纳入重启检查。缺少已安装内核清单时，不能给出 PASS。NVIDIA 6.17 和 Ubuntu 26.04 的映射还会根据源码包的最低版本检查 [Fragnesia 和 Dirty Frag](https://ubuntu.com/security/CVE-2026-46300)。新下载的表不能静默移除客户端自带的内核映射。如果表中缺少这些映射，客户端会报告不匹配并保留随客户端安装的表。

在 Ubuntu 22.04 和 24.04 上，基于 GA `linux` 源码包构建的 `generic` 和 `generic-64k` 内核（5.15 和 6.8）还会针对 [CVE-2026-64531](https://ubuntu.com/security/CVE-2026-64531) 和 [CVE-2026-64378](https://ubuntu.com/security/CVE-2026-64378)，逐项根据 Ubuntu 跟踪器进行评级。[CVE-2026-46227](https://ubuntu.com/security/CVE-2026-46227)（SCTP `SCTP_SENDALL` 容器逃逸）和 [CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432)（`ip_options_build()` 中 IPv4 `inet_opt` 的释放后使用漏洞）的评级覆盖 Ubuntu 22.04、24.04 和 26.04 中跟踪器所列出的所有内核源码包：GA、HWE、云内核（AWS、Azure、GCP、Oracle、IBM、GKE）、NVIDIA、lowlatency、FIPS、realtime 等。最低版本表为每个源码包保留一行。正在运行的内核版本字符串中的内核系列和变体用于选择对应行。跟踪器状态为 `needed`、`pending`、`deferred` 或 `ignored`（例如已停止维护）时，检查失败，因为 Ubuntu 尚未发布该内核的修复。状态为 `released` 时，在标准安全公告宽限期结束后，将正在运行的 ABI 与已发布的修复 ABI 进行比较。没有对应行的内核会得到未知结果，因为审计无法检查它，例如自定义或主线构建、比表中版本更新的软件包，或审计无法解析的版本字符串。匹配多行的内核同样得到未知结果。riscv64 内核没有独立的行，因为它的 `generic` 变体名称无法与 amd64 和 arm64 内核区分。前面两个 CVE 仅检查 GA 内核，因此不会使其他内核得到未知结果。

每日刷新还会在修复发布之前发现 Ubuntu 内核 CVE。它查询 Ubuntu CVE 搜索中自 2026-10-01 起发布且位于最近 30 天内的 `linux` CVE。如果 Ubuntu 将某个 CVE 评为 `critical`，或评为 `high` 且 CVSS v3 分数不低于 9.0，并且跟踪器将其列在 22.04、24.04 或 26.04 的 GA `linux` 包下，刷新就会添加该 CVE。新发现的 CVE 使用 `linuxCve<year>_<number>` 键，按内核分别建行，与上述 CVE 相同，每行均带有 `"discovered": true`。审计从最低版本表读取内核 CVE 分组，因此无需修改客户端即可对新发现的 CVE 进行评级。即使离开 30 天窗口，新发现的 CVE 仍会保留在表中，以便继续评估后续修复。如果新发现的 CVE 的某一行处于 `needs-triage` 状态，对应内核的结果为未知。刷新 PR 会列出每个新发现的 CVE 供审阅。如果获取的表缺少已安装表中的任一内核 CVE 分组，客户端会拒绝该表并保留已安装的表。当表超过 3 MiB 时，刷新会失败，以使其保持在客户端 4 MiB 的获取上限以内。

如果宿主机未安装 Docker，或检查范围内没有 CUDA Toolkit，结果仍为不适用。这与工具无法读取或探测失败不同，后两者的结果仍为未知。完整的裸金属 PCI 扫描若未发现 VFIO 分配，则被抽样宿主机的直通检查为不适用。UFM 控制设置需要服务商提供证据。租户检查配置在收到控制记录前会跳过这项服务商侧检查。跳过不代表互联网络通过安全认证。共享 InfiniBand 网络仍需服务商进行安全审查。

以下结果有明确的评估范围：

- **BMC/IPMI：** PASS 表示已完成的本地读取命令未返回可用的管理数据。通用 IPMI 错误响应仍记录为 `error-response`，而非访问被拒绝响应。工具缺失、超时和节点覆盖不完整时，结果仍为未知。不测试网络 BMC 接口。
- **NVLink：** 完整的拓扑扫描加上运营方对所有权的声明可以通过检查。只有在观察到的整个物理域都属于该资源分配时，才应设置 `CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED=true`。仅凭 GPU 数量不能确定所有权。证据会记录声明来源。
- **ConnectX 固件：** 解析器保留 NVIDIA 明确给出的 GA [“46.3008 或更新版本”范围](https://raw.githubusercontent.com/NVIDIA/product-security/main/2026/5699/5699.json)。对于已映射的 ConnectX-8 和 BlueField-3 固件系列，后续版本分支可以通过检查。较旧 LTS 分支的最低版本要求单独保留。未知产品不会仅因版本号更高而沿用该范围。
- **Virtio-Net：** 当前 NIC 模式经验证后，可通过当前暴露风险检查。无法读取存储中的固件时，其状态仍为未评估。启用 DPU 模式前需重新检查固件。单个 NIC 模式样本不能消除机群证据缺失或不一致的问题。
- **DPU 宿主机策略：** 已启用的 RShim 通路可能违反配置的限制策略，但这不能证明 DPU 登录成功或漏洞已被利用。运行时锁、权限和所有权需单独检查。审计不会启动 RShim 或切换模式。在 BlueField-3 上，NIC 模式下不会启动 Arm OS（[NVIDIA 模式文档](https://docs.nvidia.com/doca/archive/2-9-4/bluefield-modes-of-operation/index.html)）。

安全检查配置从完整审计中选取版本和隔离检查。使用 `-s` 或 `--show` 可在运行审计前列出适用的检查：

```console
$ cmax audit security --show
[versions] Minimum versions
  securityVersions.nvidiaDriver.status: Security Versions / NVIDIA Driver
  ...

[isolation] Security isolation
  security.januscape.status: Security / Januscape
  ...
```

使用 `--dry-run -o yaml` 可查看解析后的执行计划，这也将用于后续版本的 clustermax CLI。以下示例选择一台独立虚拟机：

```console
$ cmax audit security --vm --dry-run -o yaml
# Only audit security manifest is enabled, unrelated tests are not
version: 4
manifest_selection:
  enabled:
  - audit.audit
  disabled_count: 0
  disabled_by_phase:
    audit: 0
audit_profile:
  name: security
  dry_run: true
  command: cmax audit security
  target:
    selection: explicit
    environment: vm
    harness: standalone
  scope:
    core_collector: true
    checks:
      fabric: true
      gpu: false
      system: false
    general_findings_report: false
    standard_report: true
  artifacts:
  - audit.out
  - audit.values.json
  checks:
  - securityVersions.nvidiaDriver.status
  - securityVersions.nvidiaContainerToolkit.status
  - securityVersions.cudaToolkit.status
  - securityVersions.runc.status
  - securityVersions.docker.status
  - securityVersions.connectxFirmware.status
  - securityVersions.dcgm.status
  - securityVersions.dcgmExporter.status
  - securityVersions.virtioNetBluefield.status
  - securityVersions.virtioNetBluefield.exposure
  - securityVersions.dpuHostIsolation.status
  - security.januscape.status
  - security.guestKernel.newerInstalled
  - security.fragnesia.status
  - bmc-ipmi
  - ufm-profile
  - pcie-passthrough
  - nvlink-boundary
```

解析后的计划仅启用 `audit.audit`。它使用标准产物文件、进度封装层和报告格式化器。在 Slurm 上，安全检查配置使用专项采集器，执行报告所需的工作节点安全信息采集、容器版本信息采集和后端互联网络检查。

每次实际审计都会在采集数据前报告目标。交互式运行需要确认。默认选项会取消审计并返回退出码 130：

```text
# ClusterMAX audit target
  Command: cmax audit security
  Target: Local machine
  Host: <hostname>
  System: macOS <version> (<architecture>)
  Access: current shell; cluster credentials are not used
  Compatibility: limited; Linux GPU checks can report unavailable components
  Selection: auto-detected
Run this audit? [y]es, [c]hange target or access, [N]o:
```

输入 `c` 可选择本地机器、Kubernetes 集群或 Slurm 集群。选择 Kubernetes 时可提供 kubeconfig 路径和上下文，并会在审计开始前验证连接。选择 Slurm 时会验证当前 Slurm 客户端会话。

确认目标正确后，运行安全审计。该命令默认使用 `-v` 详细级别。
```bash
cmax audit security
```

使用 `-vvv` 可查看最详细的输出。
```bash
cmax audit security -vvv
```

## 使用说明

交互式审计会在启动标志下方显示一段简短的集群祈愿语。祈愿语仅用于装饰，不会改变 GPU 设置或审计结果。管道输出、帮助、版本输出，以及 `--show` 或 `--dry-run` 等查看命令中不会显示祈愿语。设置 `CLUSTERMAX_PROGRESS=0` 可隐藏启动标志、祈愿语和进度显示。

该命令会自动检测 Slurm、Kubernetes、容器、虚拟机、macOS 和独立主机，并与用户交互确认选择。若要跳过此确认并强制 CLI 使用指定方式，可使用 `--local`、`--slurm`、`--k8s`、`--container`、`--vm` 或 `--standalone`。使用 `--kubeconfig PATH` 可选择 Kubernetes 凭据。在非交互式运行中，显式目标选项即表示确认该目标。使用 `--yes` 可直接接受自动检测的目标而不显示提示。

请从登录节点运行 Slurm 审计，从具有 `kubectl` 访问权限的机器运行 Kubernetes 审计。如果独立模式命令在集群节点上启动，或 Slurm 命令在计算节点上启动，CLI 会在开始工作前显示证据、范围和建议使用的命令。

不匹配提示菜单默认取消操作。选择 `c`，再用 `y` 确认，可继续在当前主机上运行。选择 `r` 可查看经过脱敏的检测详情和[公开问题表单](https://github.com/SemiAnalysisAI/ClusterMAX/issues/new)。CLI 不会上传任何内容。分享前请检查预览，不要附带凭据、集群名称、主机名或原始日志。

`--yes` 或 `--allow-cluster-node` 会跳过不匹配提示菜单，并在当前主机上运行所选目标。没有终端时，目标不匹配的运行会停止，除非提供了这两个选项之一。

对于运行在 Kubernetes 上的 Slurm（包括 Slinky），CLI 会将 Slurm 角色与运行时环境分开显示。当自动检测发现两个接口均可访问时，它会询问使用哪个接口。`--yes` 保留自动检测的接口，`--slurm` 或 `--k8s` 则选择相应接口。没有终端时，运行会停止，除非提供了其中一个选项。显式指定接口会跳过此选择，但从计算节点运行 Slurm 仍需要 `--yes`、`--allow-cluster-node` 或交互式确认。

回归测试使用合成信号覆盖取消、报告、覆盖默认行为、混合接口和访问检查失败等情况。这些测试不能证明系统已通过实际集群验证。

用户可以多次运行命令。默认情况下，每次运行都会在 `~/.clustermax/audit/` 下写入带有时间戳的产物。

安全检查失败时返回退出码 2。如果调用方需要退出码 0，可使用 `--exit-zero`。

有关标准、报告格式和证据限制，请参阅[运行安全审计](#运行安全审计)一节。

## 运行集群审计

版本 0.3.0 运行核心审计。使用 `-s` 或 `--show` 可列出全部检查，而不采集数据：

```bash
cmax audit --show
```

预览将完整审计检查分为以下检查配置：

| 检查配置 | 范围 |
|---|---|
| `versions` | 组件版本及最低版本要求。 |
| `isolation` | 内核、虚拟化和租户隔离。 |
| `hardware` | GPU、内存和输入输出虚拟化。 |
| `software` | GPU 开发和诊断工具。 |
| `containers` | 容器运行时及其 GPU 集成。 |
| `orchestration` | Slurm 工作节点、Pyxis 和 Kubernetes kubelet。 |
| `networking` | 互联网络拓扑、适配器命名和 NCCL 配置。 |
| `storage` | 对存储组件安装和配置进行通过或不通过的判定。 |
| `health` | 节点健康和 GPU 遥测检查。 |

将检查配置用作审计子命令，即可选取对应的检查：

```bash
cmax audit hardware --show
cmax audit hardware
cmax audit networking --slurm
```

所有具名检查配置都使用同一个核心采集器封装层、进度显示、产物目录和报告格式化器。检查配置将补充检查和终端报告限制在所选审计检查范围内。共享采集器仍会记录所选检查需要的信息。Slurm 安全检查配置还会省略完整审计中不提供安全证据的部分。

完整审计会读取保留的最近七天内核历史记录，以检查 GPU 错误。它会检查当前 Slurm 资源分配中的每个节点，以及每个 Kubernetes GPU 节点。如果无法读取 journal，则使用本次启动的 `dmesg` 缓冲区。

每次实际运行检查配置都会保存 `audit.out` 和 `audit.values.json`。如果安全检查配置的标准报告中包含失败的检查，则返回退出码 2。自动化系统需要退出码 0 时，可使用 `--exit-zero`。

所有审计报告使用相同的状态块。输出到终端时，`PASS` 为绿色，`WARNING` 为黄色，`FAIL` 为红色，`SKIPPED` 为暗色。重定向输出保持纯文本格式。默认的 `-v` 输出会显示所有通过、警告、失败和跳过的检查，还会显示每个检测到的版本、对应的最低版本，以及已发布的[最低版本表](https://www.clustermax.ai/minimum-versions)中该组件的链接，例如 [`runc`](https://www.clustermax.ai/minimum-versions#runc)。`-vv` 输出增加带标签的 CVE 和厂商文档链接。`-vvv` 输出增加问题描述和建议的修复方法。CLI 不提供低于 `-v` 的输出级别。

目标别名用于为完整审计选择环境：

```bash
cmax audit slurm
cmax audit k8s
cmax audit standalone
cmax audit vm
cmax audit container
```

这些命令分别等同于对应的 `--slurm`、`--k8s`、`--standalone`、`--vm` 和 `--container` 选项。

Slurm 审计通过 Pyxis 添加到 `srun --help` 中的容器选项检查 Pyxis。如果软件包元数据可用，会记录已安装的软件包版本。该检查不会启动容器或等待 GPU 资源分配。如果这些选项不可用，审计会提供 [NVIDIA Pyxis 安装说明](https://github.com/NVIDIA/pyxis#installation)链接。

完整审计还会评估已发布标准中可从集群目标得出二元结果的项目。这些检查验证调度器的 CUDA 设备分配、Lmod、Kubernetes ReadWriteMany 存储和 Nsight Compute 性能分析权限。需要商业、合同、性能、可靠性、服务商侧或横向扩展网络证据的标准不在此次审计范围内。

选择目标后，审计仅运行适用于该目标的检查。独立容器、虚拟机或裸金属主机会省略所有仅适用于 Slurm 或 Kubernetes 的检查，包括 GRES、Pyxis、调度器拓扑、多节点 NCCL、健康检查程序、prolog、NHC、自动修复和 kubelet CPU Manager。

Kubernetes 审计会跨所有命名空间发现服务商组件，因为托管服务可能使用服务商专用命名空间和当前的 Kubernetes 应用标签。审计还会区分真正的容器运行时二进制文件与命令名为 `docker` 的兼容性链接。当审计发现 Promtail 与 Loki 或 Elasticsearch 一起使用时，会将聚合系统报告为日志栈，而仅将 Promtail 报告为已检测到的日志传输代理。

Kubernetes 的 BMC 和 IPMI 检查使用已确认的 Kubernetes 身份创建特权 Pod，挂载各工作节点的宿主机根目录。报告会列出每个已检查节点，并说明机群覆盖范围。此证据证明的是该管理身份能够访问的内容，不能证明普通工作负载 Pod 也能访问同一个本地管理接口。默认最多检查 32 个工作节点。如果更大的机群需要完整覆盖，可将 `CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT` 设为更大的正整数。由于探测以宿主机 root 身份运行，Kubernetes 上暴露的 BMC 被评为 WARNING，而非 CRITICAL：裸金属主机上的 root 通常可以访问带内 BMC。请确认租户不能调度特权 Pod，也不能挂载宿主机 IPMI 设备。在 Slurm 和独立主机上，探测以租户用户身份运行，因此暴露的 BMC 仍为 CRITICAL。

专项安全审计（`cmax audit security`）会在每台 GPU 主机上评估宿主机级最低版本要求，而非仅检查被抽样的工作节点。检查对象包括 GPU 驱动、NVIDIA Container Toolkit、runc、Docker、ConnectX 固件、DCGM 和内核安全公告。每项检查都会报告结果最差的主机及其名称，并列出各主机的结果。ConnectX 设备以 `host/device` 格式列出。如果某台 GPU 主机无法读取，原本可通过的检查会保持未知状态。Kubernetes 在各节点上复用 BMC 宿主机根目录 Pod；Slurm 使用 `--immediate=30` 在每个 GPU 节点上运行一个短时的单 GPU 作业步骤，因此繁忙节点会被报告为未读取，而非一直等待。默认最多读取 32 台 GPU 主机；更大的机群可设置 `CLUSTERMAX_AUDIT_SECURITY_HOST_LIMIT`。

Kubernetes 的完整审计、安全审计和隔离审计还会检查 ClusterRole 和 ClusterRoleBinding 是否授予对 `nodes/proxy` 的 `get` 权限。报告会列出主体、角色、绑定和节点名称限制，包括通配符授权。发现匹配的授权时，结果为 `FAIL`。管理权限可能是有意授予的，也会列出供审查。清单不完整时，结果为 `WARNING`，除非审计已发现授权。此检查只读取 RBAC 配置，不连接 kubelet，也不在 Pod 内执行命令。请参阅 [Kubernetes kubelet 授权文档](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)和 [Graham Helton 的 nodes/proxy 文章](https://grahamhelton.com/blog/nodes-proxy-rce)。

独立模式审计也会省略横向扩展网络检查。它不检查 InfiniBand、RoCE、RDMA、HCA 命名、PKey、UFM、SHARP、互联网络拓扑或 GPUDirect RDMA。报告会将相应标准标记为 `SKIPPED`。Slurm 和 Kubernetes 审计仍保留横向扩展网络检查。

独立模式审计仍会读取本地 PCI 设备列表，以确定 NVIDIA GPU 驱动安全标准是否适用于该主机。

平台配置检查有各自的入口。硬件检查配置运行 `vm-iommu-check.py` 和 `arm-smmu-virtualization-check.py`。网络检查配置在 Slurm 上运行 `nccl-topology-file-check.py`，在 Slurm 或 Kubernetes 上运行 `nccl-ib-qps-check.py`。这些入口在一次审计中复用同一次宿主机信息采集。

核心审计采集集群、宿主机、GPU、存储、网络、健康和安全数据，不运行计划中的性能或可靠性测试。

每个审计命令都会显式设置其执行配置和所选执行环境。继承的 `CLUSTERMAX_AUDIT_SCOPE` 或 `CLUSTERMAX_AUDIT_HARNESS` 值不能改变已确认的选择。`cmax audit` 使用完整检查配置。每个具名子命令使用与其对应的专项检查配置。

使用以下命令运行或查看核心审计：

```bash
cmax audit
cmax audit review
```

ClusterMAX 会检测 Slurm、Kubernetes 或独立机器。检测不正确时，可使用 `--slurm`、`--k8s`、`--local` 或 `--standalone`。该命令使用与安全审计相同的目标报告和确认流程。

每次审计会将结果保存在 `~/.clustermax/audit/<timestamp>/` 下。如果需要与数据导入兼容的 `<root>/<cluster>/<timestamp>/audit/` 目录结构，可设置 `CLUSTERMAX_RUNS_ROOT`。

审计是只读的。本节列出了要求、检查和输出文件。

使用 `cmax audit review` 可打开最近保存的审计。也可以指定审计目录、`audit.values.json` 文件或 `audit.out` 文件：

```bash
cmax audit review runs/<cluster>/<timestamp>/audit/audit.out
cmax audit review --command 'find runc'
cmax audit review --command 'show securityVersions.runc.status'
```

使用 `-v` 可包含通过和跳过的检查。使用 `-vv` 可包含采集到的证据。使用 `-vvv` 可包含建议的修复方法和带标签的参考 URL。使用 `--command raw` 可打印已保存的采集器日志。使用 `--no-interactive` 可打印审阅结果后退出。

## 仓库内容

| 路径 | 内容 |
|---|---|
| `cmax/` | 命令代码和 `cmax.yaml` 配置。 |
| `cmax/scripts/1-audit/` | 执行审计的脚本。 |
| `tests/audit/` | 所有审计测试、测试数据和测试辅助工具。 |

本次发布不包含服务商结果、内部笔记、私有仪表盘、基准测试实现、随附数据或数据库代码。

## 许可证

所有已发布的 ClusterMAX 源代码均采用 Apache License 2.0。请参阅 [LICENSE](LICENSE)。
