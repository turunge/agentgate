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
| Örnek politikalar (4) | ✅ |
| `core/schemas.py` — Pydantic modelleri | ✅ |
| `core/normalize.py` — yol/host/komut normalizasyonu | ✅ |
| `core/policy.py` — yükleme + değerlendirme motoru | ✅ |
| `tests/` — 67 test | ✅ |
| MCP proxy | ⬜ |
| Inspector (Docker sandbox) | ⬜ |
| Event store + replay | ⬜ |
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
tests/
  test_policy.py    # 13 senaryo + semantik testleri
  test_normalize.py
  test_schemas.py   # şema ↔ model ayrışma kontrolü
docs/
  data-model.md
  schemas/*.schema.json
policies/*.yaml
```

## Sıradaki adım

`proxy/` — MCP stdio taşıması, `tools/call` kesme, `core.policy` ile karar, olay kaydı.
V1 kabul kriteri: `docs/data-model.md` §6'daki 7 olaylık senaryonun uçtan uca `deny`
üretmesi ve replay'in aynı sonucu vermesi.

## Etik

Yalnızca sahip olunan veya açık kaynak MCP sunucuları, izole ortamda test edilir.
Üretim sistemlerine yönelik kullanım kapsam dışıdır.
