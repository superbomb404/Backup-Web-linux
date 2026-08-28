# PVE Backup Web

PVE Backup Web 是一个面向 Linux / Proxmox VE 的轻量级 Web 备份面板。它可以让管理员配置可访问的服务器目录和群晖 NAS 信息，普通用户通过浏览器选择授权目录中的文件或文件夹，并把备份上传到群晖 File Station，再移入 Cloud Sync 同步目录。

## 功能说明

- Web 登录面板，默认使用 HTTPS，首次启动自动生成自签证书。
- 首次启动自动创建 `admin` 管理员账号，并把初始密码写入运行目录下的 `bootstrap-admin-password`。
- 管理员可添加备份目录根路径，并为不同用户分配可见目录。
- 支持备份单个文件，也支持把目录打包为 `.tar.gz` 后上传。
- 上传到群晖暂存目录后，自动移动到 Cloud Sync 同步目录。
- 实时任务进度显示，包含上传字节数、速度、任务阶段和错误信息。
- 可取消、重试、删除任务，并手动刷新或标记云端完成状态。
- 管理后台包含用户管理、目录权限、群晖连接配置、公告、日志、HTTPS 证书和登录风控。
- 登录失败达到阈值后启用验证码，并可配置临时或永久封禁策略。
- 状态存储使用 SQLite，敏感配置会使用本机 `app.key` 加密后保存。

## 目录结构

```text
app/                      Go Web 服务源代码
  main.go                 后端、前端页面和群晖 API 集成
  go.mod
  go.sum
  config.example.json     配置示例
dist/
  pve-backup-service.sh   systemd 服务安装脚本
tools/
  remote_ssh.py           可选 SSH 辅助脚本
```

## 编译教程

需要 Go 1.22 或更新版本。

### 在 Linux / PVE 上编译

```bash
cd app
go mod download
go build -trimpath -ldflags="-s -w" -o ../dist/pve-backup-web .
```

### 在 Windows 上交叉编译 Linux amd64

```powershell
cd app
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w" -o ../dist/pve-backup-web-linux-amd64 .
```

## 快速运行

```bash
mkdir -p /opt/pve-backup-web
cp dist/pve-backup-web /opt/pve-backup-web/
chmod +x /opt/pve-backup-web/pve-backup-web
cd /opt/pve-backup-web
./pve-backup-web
```

默认监听地址为 `:60000`，浏览器访问：

```text
https://服务器IP:60000
```

首次管理员账号：

```text
用户名：admin
密码：查看 /opt/pve-backup-web/bootstrap-admin-password
```

首次登录后建议立即修改管理员密码。

## 配置说明

程序会在运行目录自动生成 `config.json`。也可以参考 `app/config.example.json` 提前创建。

```json
{
  "listen_addr": ":60000",
  "public_base_url": "https://your-server-ip:60000",
  "synology_base_url": "https://your-nas:5001",
  "synology_username": "your-synology-user",
  "synology_password": "",
  "synology_staging_dir": "/NVME/.pve-backup-incoming",
  "synology_cloud_target_dir": "/NVME/PVEBackup",
  "verify_tls": false,
  "captcha_after_failures": 2,
  "max_login_failures": 10,
  "ban_duration_minutes": 0,
  "permanent_ban": true
}
```

说明：

- `listen_addr`：Web 服务监听地址，默认 `:60000`。
- `public_base_url`：对外访问地址，用于生成默认自签证书信息。
- `synology_base_url`：群晖 DSM 地址，例如 `https://192.168.1.10:5001`。
- `synology_staging_dir`：上传暂存目录，程序会先上传到这里。
- `synology_cloud_target_dir`：最终移入的 Cloud Sync 同步目录。
- `verify_tls`：连接群晖时是否校验 TLS 证书；自签证书环境可设为 `false`。
- `ban_duration_minutes` 为 `0` 且 `permanent_ban` 为 `true` 时，达到失败阈值后永久封禁。

群晖账号需要具备 File Station 上传、建目录、移动文件，以及读取 Cloud Sync 状态的权限。

## systemd 部署

Release 包里包含 `pve-backup-service.sh`，也可以使用仓库内的 `dist/pve-backup-service.sh`。

```bash
sudo mkdir -p /opt/pve-backup-web
sudo cp pve-backup-web /opt/pve-backup-web/
sudo cp pve-backup-service.sh /opt/pve-backup-web/
sudo chmod +x /opt/pve-backup-web/pve-backup-web /opt/pve-backup-web/pve-backup-service.sh

cd /opt/pve-backup-web
sudo ./pve-backup-service.sh install
sudo ./pve-backup-service.sh enable
sudo ./pve-backup-service.sh start
sudo ./pve-backup-service.sh status
```

卸载服务：

```bash
cd /opt/pve-backup-web
sudo ./pve-backup-service.sh uninstall
```

## 运行期文件

以下文件会在运行目录生成，不应提交到 Git：

- `config.json`
- `state.db`、`state.db-*`
- `state.json`
- `app.key`
- `server.crt`
- `server.key`
- `bootstrap-admin-password`
- `work/`

备份运行前，请妥善保存 `app.key` 和 `state.db`。丢失 `app.key` 后，SQLite 中的加密配置无法解密。

## Release 下载

最新版本可在 GitHub Releases 页面下载 Linux amd64 可执行文件和 systemd 安装脚本。

```bash
chmod +x pve-backup-web-linux-amd64
./pve-backup-web-linux-amd64
```

## 许可证

本项目使用 MIT License。
