# caddy-dns-aliesa

为 [Caddy](https://caddyserver.com/) 提供阿里云 [边缘安全加速 ESA](https://help.aliyun.com/zh/edge-security-acceleration/esa/) DNS 记录的插件，基于 [libdns](https://github.com/libdns/libdns) 接口实现，可用于 ACME DNS-01 验证以及常规 DNS 记录管理。

## 功能

- 支持 Caddy 的 `dns` / `acme_dns` 指令
- 支持 ACME DNS-01（包括泛域名证书）
- 自动根据域名查找 ESA 站点（Site）
- 支持 A/AAAA、CNAME、TXT、MX、NS、SRV、CAA、URI、CERT、SSHFP、SMIMEA、TLSA 等记录
- 支持 ESA 的代理加速（Proxied）配置
- 支持 STS `security_token`
- 支持中国内地（`cn-hangzhou`）和新加坡（`ap-southeast-1`）接入点
- 支持通过环境变量提供 AccessKey

## 安装

使用 [xcaddy](https://github.com/caddyserver/xcaddy) 重新构建 Caddy：

```bash
xcaddy build --with github.com/xiedada05/caddy-dns-aliesa
```

本地开发时可以直接从当前目录构建：

```bash
xcaddy build --with github.com/xiedada05/caddy-dns-aliesa=.
```

## Caddyfile 配置

### 为单个站点配置

```caddyfile
example.com {
    tls {
        dns aliesa {
            access_key_id {env.ALIESA_ACCESS_KEY_ID}
            access_key_secret {env.ALIESA_ACCESS_KEY_SECRET}
        }
    }

    respond "Hello, ESA!"
}
```

### 全局配置

```caddyfile
{
    acme_dns aliesa {
        access_key_id {env.ALIESA_ACCESS_KEY_ID}
        access_key_secret {env.ALIESA_ACCESS_KEY_SECRET}
    }
}

example.com {
    respond "Hello, ESA!"
}
```

### 使用代理加速的站点

```caddyfile
example.com {
    tls {
        dns aliesa {
            access_key_id {env.ALIESA_ACCESS_KEY_ID}
            access_key_secret {env.ALIESA_ACCESS_KEY_SECRET}
            proxied true
            biz_name web
        }
    }
}
```

### 新加坡接入点

```caddyfile
example.com {
    tls {
        dns aliesa {
            access_key_id {env.ALIESA_ACCESS_KEY_ID}
            access_key_secret {env.ALIESA_ACCESS_KEY_SECRET}
            region_id ap-southeast-1
        }
    }
}
```

## 配置项

| 配置项 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `access_key_id` | 是 | 环境变量 | 阿里云 AccessKey ID |
| `access_key_secret` | 是 | 环境变量 | 阿里云 AccessKey Secret |
| `security_token` | 否 | 空 | STS 临时凭证的 SecurityToken |
| `region_id` | 否 | `cn-hangzhou` | ESA API 区域，可选 `cn-hangzhou`、`ap-southeast-1` |
| `endpoint` | 否 | 自动生成 | 自定义 ESA API 地址，主要用于测试或私有网关 |
| `ttl` | 否 | `600` | 记录默认 TTL，单位秒；取值 `1` 表示自动，其余为 `30`-`86400` |
| `proxied` | 否 | 自动 | 新建 A/AAAA、CNAME 记录是否开启 ESA 代理加速 |
| `biz_name` | 否 | `web` | 开启代理加速时的业务场景：`web`、`api`、`image_video`、`file`、`ai` |

`proxied` 不设置时：

- NS 接入的站点：新建 A/AAAA、CNAME 记录默认关闭代理
- CNAME 接入的站点：新建 A/AAAA、CNAME 记录默认开启代理（这类站点的记录不能关闭代理）

TXT 等 DNS-01 验证记录不会开启代理。

## 环境变量

如果 Caddyfile 中没有显式配置 AccessKey，插件会依次读取：

```bash
ALIESA_ACCESS_KEY_ID
ALIESA_ACCESS_KEY_SECRET
ALIESA_SECURITY_TOKEN
```

也兼容阿里云 SDK 的标准变量名：

```bash
ALIBABA_CLOUD_ACCESS_KEY_ID
ALIBABA_CLOUD_ACCESS_KEY_SECRET
ALIBABA_CLOUD_SECURITY_TOKEN
```

Windows PowerShell 示例：

```powershell
$env:ALIESA_ACCESS_KEY_ID = "your-access-key-id"
$env:ALIESA_ACCESS_KEY_SECRET = "your-access-key-secret"
```

## JSON 配置示例

```json
{
  "apps": {
    "tls": {
      "automation": {
        "policies": [
          {
            "subjects": ["example.com"],
            "issuers": [
              {
                "module": "acme",
                "challenges": {
                  "dns": {
                    "provider": {
                      "name": "aliesa",
                      "access_key_id": "your-access-key-id",
                      "access_key_secret": "your-access-key-secret",
                      "region_id": "cn-hangzhou"
                    }
                  }
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

## RAM 权限

建议创建独立的 RAM 用户，并授予以下最小权限：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "esa:ListSites",
        "esa:ListRecords",
        "esa:GetRecord",
        "esa:CreateRecord",
        "esa:UpdateRecord",
        "esa:DeleteRecord"
      ],
      "Resource": "*"
    }
  ]
}
```

生产环境建议将 `Resource` 限制到具体站点 ARN，并只授予实际需要的操作。

## 工作说明

- 域名（Zone）必须已经添加到阿里云 ESA。插件不会自动创建站点。
- Caddy 传入的 zone 可以与 ESA 站点同名，也可以是 ESA 站点的子域名；插件会匹配最长的站点后缀。
- ESA 使用 `A/AAAA` 作为 A 和 AAAA 的共同记录类型，插件会根据 IP 地址自动区分。
- ESA 的 TTL 最小为 30 秒。libdns 传入 0 时使用配置的 `ttl`。
- `SetRecords` 通过“删除同名同类型记录再创建”实现。ESA 没有批量事务，因此该操作不是原子的；DNS-01 流程使用的是 `AppendRecords` / `DeleteRecords`，不受影响。重建后的 A/AAAA、CNAME 记录，其代理状态由 `proxied` 配置或站点接入类型决定。
- 记录操作使用阿里云 RPC 签名（HMAC-SHA1），与官方 ESA SDK 一致。

## 开发

```bash
go test ./...
go vet ./...
```

## License

Apache License 2.0
