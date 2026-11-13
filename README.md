# AgentGate

LLM ajanlarının araç çağrılarını iki düzlemde denetleyen güvenlik katmanı:

- **Inspector:** MCP sunucusunu izole sandbox'ta çalıştırır, gerçekte ne yaptığını kaydeder ve bildirdiğiyle karşılaştırır → Capability Manifest.
- **Proxy:** çalışma anında araç çağrılarını keser, içerik kökenini izler, politikaya göre izin/ret/onay verir.

Mimari: [`ARCHITECTURE.md`](ARCHITECTURE.md)
Veri modeli: [`docs/data-model.md`](docs/data-model.md)

## Durum

| Katman | Durum |
|---|---|
| JSON Schema sözleşmeleri (5) | ✅ |
| Örnek politikalar (5) | ✅ |
| `core/schemas.py` — Pydantic modelleri | ✅ |
| `core/normalize.py` — yol/host/komut normalizasyonu | ✅ |
| `core/policy.py` — yükleme + değerlendirme motoru | ✅ |
| `proxy/capabilities.py` — araç → capability çıkarımı | ✅ |
| `proxy/core.py` — kesme + karar + taint + kısıt uygulama | ✅ |
| `proxy/events.py` — hash-chain'li JSONL olay kaydı | ✅ |
| `proxy/server.py` — MCP stdio taşıması | ✅ |
| `proxy/replay.py` — politika değişikliği farkı | ✅ |
| `tests/` — 91 test (uçtan uca dahil) | ✅ |
| Inspector (Docker sandbox) | ⬜ |
| UI | ⬜ |

## Çalıştırma

```bash
python3 -m venv .venv
.venv/bin/pip install pydantic pyyaml jsonschema pytest

.venv/bin/python -m pytest -q
```

## Yapı

```
core/
  schemas.py     # docs/schemas/*.json ile birebir modeller
  normalize.py   # capability hedefi normalizasyonu
  policy.py      # load_policy / evaluate / decide
proxy/
  capabilities.py  # araç adı + argüman -> Capability + risk
  core.py          # tools/call kesme, karar, taint, redaksiyon
  events.py        # ULID, hash-chain, JSONL
  server.py        # stdio köprüsü (python -m proxy.server ... -- <mcp server>)
tests/
  test_policy.py      # 13 senaryo + semantik testleri
  test_normalize.py
  test_schemas.py     # şema ↔ model ayrışma kontrolü
  test_events.py      # hash-chain + redaksiyon
  test_proxy_core.py  # karar akışı, taint, kısıtlar
  test_proxy_e2e.py   # gerçek süreçlerle uçtan uca
docs/
  data-model.md
  schemas/*.schema.json
policies/*.yaml
```

## Proxy'yi çalıştırma

```bash
.venv/bin/python -m proxy.server \
  --policy policies/demo-proxy.yaml \
  --workspace /ws \
  --events events/session.jsonl \
  --allowlist git,ls \
  -- python path/to/mcp_server.py
```

## Replay

```bash
.venv/bin/python -m proxy.replay events/session.jsonl \
  --policy policies/coding-agent.yaml --workspace /ws
```

Kaydedilmiş kararlarla yeni politikanın kararlarını karşılaştırır; fark varsa
çıkış kodu 1 döner (CI'da kullanılabilir), zincir bozuksa 2.

## Sıradaki adım

Inspector: Docker sandbox + declared/observed capability diff → Manifest.
V1 kabul kriteri karşılandı: 7 olaylık senaryo uçtan uca `deny` üretiyor,
olay zinciri doğrulanıyor ve aynı politikayla replay sıfır fark veriyor.

## Etik

Yalnızca sahip olunan veya açık kaynak MCP sunucuları, izole ortamda test edilir.
Üretim sistemlerine yönelik kullanım kapsam dışıdır.
