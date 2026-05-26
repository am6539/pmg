# Plan: Aikido Intel + SafeDep Combined Malware Detection

## Mục tiêu

Thêm Aikido Intel (free, no-auth) làm analyzer thứ hai chạy song song với SafeDep.  
Block nếu **một trong hai** flag package. Toàn bộ event vẫn gửi về pmg-cloud tự host.  
pmg-cloud mirror Aikido feed để org có thể chạy hoàn toàn air-gapped.

## Architecture

```
[pmg agent — npm install]
       │
       ├── SafeDep malysis API (gRPC) ──► ActionBlock / ActionAllow
       └── Aikido Intel analyzer
               │
               ▼
         aikido_intel.base_url
               │
       ┌───────┴────────────────────────────┐
       │ default (internet)                 │ air-gapped
       ▼                                    ▼
malware-list.aikido.dev              pmg-cloud:8080
/malware_predictions.json       /malware_predictions.json
/malware_pypi.json              /malware_pypi.json
                                     │
                                     └──(cache 1h)──► malware-list.aikido.dev

[pmg agent] ──── gRPC SyncEvents ────► pmg-cloud (audit log + dashboard)
```

---

## Phase 1 — Standalone Aikido analyzer + tests

**Exit criterion:** `go test ./analyzer/... -race -count=1` pass. Chưa wire vào flow nào.

| # | File | Việc làm |
|---|------|---------|
| 1 | `config/config.go` | Thêm `AikidoIntelConfig` struct (enabled, base_url, cache_ttl, request_timeout) + `AikidoCacheDir()` helper + default values |
| 2 | — | Xác nhận schema JSON Aikido feed bằng curl, document inline |
| 3 | `analyzer/aikido_intel.go` | Implement analyzer: fetch feed, cache disk (TTL 1h), in-memory snapshot, lookup O(1), graceful degradation khi network fail |
| 4 | `analyzer/aikido_intel_test.go` | Unit tests: hit/miss, cache hit, cache expire, network fail (with/without disk cache), unsupported ecosystem, concurrent, malformed JSON |

**Chi tiết Step 3 — aikido_intel.go:**
- `Name()` → `"aikido-intel"`
- `Analyze()` → map ecosystem → feed; load snapshot; nếu không load được thì `log.Warnf` + `ActionAllow`
- Hit: `ActionBlock`, `IsMalware: true`, `IsVerified: true`, `AnalysisID: "aikido:<ecosystem>:<name>@<version>"`
- Phase 1 version matching: exact string + wildcard `*`; range matching Phase 3

---

## Phase 2 — Wire vào guard flow (common_flow)

**Exit criterion:** `pmg npm install <malicious-pkg>` block với cả 2 analyzers chạy.

| # | File | Việc làm |
|---|------|---------|
| 5 | `internal/flows/common_flow.go` | Append Aikido analyzer vào `analyzers` khi `enabled: true`; constructor error → warn + skip |
| 6 | `config/config.template.yml` | Thêm section `aikido_intel:` với comments đầy đủ |

**Config template mới:**
```yaml
# Aikido Intel — free community malware feed, no API key required.
# Runs alongside SafeDep; installs are blocked if either source flags a package.
aikido_intel:
  enabled: true
  # Leave empty to use Aikido's public feed.
  # Set to your pmg-cloud URL for air-gapped / self-hosted mode.
  base_url: "https://malware-list.aikido.dev"
  cache_ttl: 1h
  request_timeout: 10s
```

---

## Phase 3 — Wire vào proxy flow + version range matching

**Exit criterion:** Proxy mode cũng được bảo vệ. Version ranges match đúng.

| # | File | Việc làm |
|---|------|---------|
| 7 | `analyzer/composite.go` | `compositeAnalyzer`: fan-out N analyzers, first-block-wins; error từ 1 không break cái kia |
| 8 | `analyzer/composite_test.go` | Tests: single pass-through, block-from-first-wins, error-from-one-ok |
| 9 | `internal/flows/proxy_flow.go` | `createAnalyzer()` trả composite khi cả 2 enabled |
| 10 | `analyzer/aikido_intel.go` | Harden version matching: semver cho npm (`Masterminds/semver/v3`), PEP 440 cho PyPI |

---

## Phase 4 — pmg-cloud mirror (air-gapped support)

**Goal:** pmg-cloud proxy + cache Aikido feeds. Agent chỉ cần trỏ `base_url` về pmg-cloud.  
Toàn bộ traffic ở trong mạng nội bộ, không cần Internet trên máy agent.

| # | File | Việc làm |
|---|------|---------|
| 11 | `dashboard/malware_mirror.go` | Fetch Aikido feeds (npm + pypi), cache in-memory + disk (TTL 1h), serve raw JSON |
| 12 | `dashboard/handler.go` | Thêm routes: `GET /malware_predictions.json`, `GET /malware_pypi.json`, `GET /api/malware/status` |
| 13 | `dashboard/static/index.html` | Dashboard: "Feed Status" page — last updated, source, bytes cho mỗi feed |

**Routes pmg-cloud (path khớp với Aikido để agent không cần config khác nhau):**
```
GET /malware_predictions.json  → serve cached npm feed
GET /malware_pypi.json         → serve cached pypi feed
GET /api/malware/status        → { npm: {last_updated, bytes, ok}, pypi: {last_updated, bytes, ok} }
```

**Config pmg phía agent (air-gapped):**
```yaml
aikido_intel:
  enabled: true
  base_url: "http://your-pmg-cloud:8080"  # thay vì malware-list.aikido.dev
```

---

## Phase 5 — Polish (optional)

| # | File | Việc làm |
|---|------|---------|
| 14 | `analyzer/aikido_intel.go` | Async background refresh — serve stale cache ngay, refresh ngầm sau |
| 15 | `cmd/aikido/` | `pmg aikido refresh` để warm cache thủ công trong CI |

---

## Risks

| Risk | Mức độ | Mitigation |
|------|--------|------------|
| Aikido feed schema thay đổi | Medium | Tolerant parser (không dùng `DisallowUnknownFields`), graceful degradation |
| Feed lớn, load chậm | Low | Lazy load per ecosystem, in-memory snapshot dùng lại trong process |
| Concurrent first-fetch storm | Medium | `sync.Once` per ecosystem, test với `-race` |
| False positive do version match sai | Medium | Phase 1 exact-match trước, Phase 3 range; escape hatch `--insecure-installation` |
| pmg-cloud mirror bị stale | Low | Serve stale khi Aikido fail + log warning; agent có on-disk cache riêng |

---

## Files thay đổi

**pmg (repo `am6539/pmg`):**
- `analyzer/aikido_intel.go` ← mới
- `analyzer/aikido_intel_test.go` ← mới
- `analyzer/composite.go` ← mới
- `analyzer/composite_test.go` ← mới
- `config/config.go` ← thêm AikidoIntelConfig
- `config/config.template.yml` ← thêm section aikido_intel
- `internal/flows/common_flow.go` ← wire analyzer
- `internal/flows/proxy_flow.go` ← wire composite

**pmg-cloud (local admin backend):**
- `dashboard/malware_mirror.go` ← mới
- `dashboard/handler.go` ← thêm 3 routes
- `dashboard/static/index.html` ← thêm Feed Status page

**Không thay đổi:**
- `guard/guard.go`
- `internal/audit/*`
- `proxy/interceptors/*` (signature)

---

## Success Criteria

- [ ] `go test ./... -race -count=1` pass
- [ ] Coverage ≥ 80% trên `aikido_intel.go` và `composite.go`
- [ ] Guard flow: cả 2 analyzers chạy song song, block nếu một trong hai flag
- [ ] Proxy flow: composite analyzer hoạt động
- [ ] `aikido_intel.base_url` override được (test với `httptest`)
- [ ] pmg-cloud serve `/malware_predictions.json` và `/malware_pypi.json`
- [ ] Dashboard hiển thị feed status (last updated, bytes, ok/error)
- [ ] Air-gapped: agent trỏ `base_url` về pmg-cloud, không cần Internet
- [ ] Graceful degradation: Aikido unreachable → log warning → install tiếp tục bình thường
