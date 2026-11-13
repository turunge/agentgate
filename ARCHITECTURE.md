# AgentGate — Uçtan Uca Mimari

> Çalışma adı. Alternatifler: Aegis, AgentSentry, Gatekeeper.
> Tek cümle: **Ajanların araç çağrılarını hem çalıştırmadan önce (sandbox'ta dinamik denetim) hem de çalışma anında (politika ile engelleme) denetleyen iki düzlemli bir güvenlik katmanı.**

---

## 0. Problem tanımı

Bir LLM ajanı, MCP sunucuları veya araç paketleri üzerinden gerçek dünyaya dokunur: dosya okur, HTTP isteği atar, kabuk komutu çalıştırır. İki bağımsız risk var:

1. **Tedarik zinciri riski:** Araç, tanıtımında yazanı yapmıyor olabilir. "Hava durumu" diyen bir MCP sunucusu `~/.aws/credentials` okuyabilir.
2. **Çalışma zamanı riski:** Araç temiz olsa bile ajan, okuduğu güvenilmeyen içerik yüzünden (prompt injection) onu kötüye kullanabilir. Buna "lethal trifecta" denir: *güvenilmeyen içerik + özel veriye erişim + dışa iletişim* aynı oturumda birleşirse sızıntı kaçınılmazdır.

Mevcut araçların çoğu yalnızca statik tarama (Semia, skill-file-security) ya da yalnızca çalışma zamanı kuralı yapar. AgentGate ikisini **aynı manifest ve aynı olay şeması** üzerinden birleştirir.

---

## 1. Tasarım ilkeleri

1. **Fail-closed.** Karar verilemeyen çağrı reddedilir; onay zaman aşımı reddeder.
2. **Deterministik ve tekrar oynatılabilir.** Her karar, saklanan olay + politika sürümü + kural ID'si ile yeniden üretilebilir.
3. **Kanıt > sezgi.** Her uyarı, bir olay zincirine ve kurala bağlanır. "LLM öyle dedi" bir gerekçe değildir.
4. **Ajanı değiştirme, araya gir.** MCP proxy ve ince adaptörler; ajanın koduna dokunmadan çalışır.
5. **Her özellik bir metrik üretir.** Ölçülemeyen özellik yapılmaz.

---

## 2. Üst düzey mimari

```
                          ┌──────────────────────────────────┐
                          │            AgentGate UI          │
                          │  timeline · attack graph · policy│
                          └────────────────┬─────────────────┘
                                           │ REST / WebSocket
┌───────────┐    MCP (stdio/HTTP)   ┌──────▼───────┐   MCP    ┌───────────────┐
│ LLM Agent │◄────────────────────►│ AG Proxy     │◄────────►│  MCP Server   │
│ (client)  │                      │ taint+policy │          │  (untrusted)  │
└───────────┘                      └──────┬───────┘          └───────────────┘
                                          │ events
                                  ┌───────▼────────┐
                                  │  Event Store   │  append-only, hash-chained
                                  │  + Manifest DB │
                                  └───────┬────────┘
                                          │
                          ┌───────────────▼─────────────────┐
                          │        Inspector Plane          │
                          │ sandbox · sensors · probe runner │
                          │ declared ⇄ observed diff        │
                          └───────────────┬─────────────────┘
                                          │ runs
                                  ┌───────▼────────┐
                                  │ MCP server/pkg │
                                  └────────────────┘
```

**İki döngü:**

- **Offline döngü (Inspector):** artefakt → izole sandbox → davranış kaydı → *declared vs observed* karşılaştırması → **Capability Manifest** + risk raporu + önerilen politika taslağı.
- **Online döngü (Proxy):** araç çağrısı → kaynak/taint çözümlemesi → politika değerlendirmesi → izin/ret/onay → denetim kaydı → yeniden oynatma.

İki döngü, **tek bir Capability şeması** ve **tek bir Event şeması** paylaşır. Projenin bütünlüğü burada.

---

## 3. Bileşenler

| Bileşen | Sorumluluk | Arayüz |
|---|---|---|
| `agentgate-core` | Şemalar, politika motoru, taint motoru, risk skoru, manifest diff | Python paketi |
| `agentgate-proxy` | MCP stdio + HTTP/SSE taşıma, oturum yönetimi, araç çağrısı kesme | CLI/daemon |
| `agentgate-inspector` | Sandbox orkestrasyonu, sensörler, probe üretimi, normalizasyon | CLI |
| `agentgate-store` | SQLite (WAL) + JSONL hash-chain, replay | Python paketi |
| `agentgate-api` | REST/WS, kimlik doğrulama, onay akışı | FastAPI |
| `agentgate-ui` | Timeline, graf, politika editörü, onay ekranı | React + TS |
| `agentgate-cli` | `inspect`, `run`, `replay`, `policy test`, `report` | CLI |
| adaptörler | MCP, LangChain tool wrapper, Claude Code hook, generic `@guard` | SDK |

---

## 4. Veri modeli (sözleşmeler)

Projenin kalbi bu dört şema. Bunlar sabitlenmeden kod yazılmaz.

### 4.1 Capability

```python
class Capability(BaseModel):
    kind: Literal["fs.read", "fs.write", "net.egress", "net.listen",
                  "proc.exec", "env.read", "secret.read", "llm.call",
                  "clipboard", "ipc"]
    target: str          # glob yol, host, komut adı, env adı
    constraints: dict = {}  # {"methods":["GET"], "max_bytes":...}
```

### 4.2 Manifest

```python
class Manifest(BaseModel):
    artifact: str            # repo/npm/pip yolu
    digest: str              # sha256
    declared: list[Capability]    # README/schema/package.json'dan
    observed: list[Capability]    # sandbox'tan
    undeclared: list[Capability]  # observed - declared
    findings: list[Finding]
    confidence: float
    inspected_at: datetime
    probe_suite: str         # hangi probe setiyle üretildi
```

### 4.3 Event

```python
class Event(BaseModel):
    id: str
    ts: datetime
    session_id: str
    parent_id: str | None
    actor: Literal["agent", "user", "tool"]
    type: Literal["tool_call", "tool_result", "context_inject",
                  "approval", "policy_decision", "finding"]
    tool: str | None
    args: dict | None
    provenance: list[TaintRef]     # argümanın kaynağı
    capability: Capability | None
    decision: Literal["allow", "deny", "approve"] | None
    constraints: list[dict] = []   # allow'a eklenen kısıtlar
    rule_id: str | None
    risk: int
```

### 4.4 TaintRef

```python
class TaintRef(BaseModel):
    segment_id: str
    trust: Literal["user", "tool", "untrusted_web", "file", "system"]
    source_ref: str          # URL, dosya yolu, tool adı
    match: Literal["exact", "shingle", "embedding"]
    score: float
```

### 4.5 PolicyDecision

```python
class PolicyDecision(BaseModel):
    decision: Literal["allow", "deny", "approve"]
    rule_id: str
    reason: str          # insan dili, UI'da gösterilir
    constraints: list[Constraint] = []
```

---

## 5. Inspector plane — akış

1. **Edinme:** `git clone` / npm / pip / yerel yol. SHA-256 + SBOM (CycloneDX).
2. **Statik geçiş:** Araç tanımlarını ve açıklamalarını çıkar (MCP `tools/list`, schema, README). `declared` capability'leri topla. Bariz risk kalıplarını işaretle (`subprocess`, `eval`, `requests`, `os.environ`).
3. **Sandbox kurulumu:** Aşağıdaki sertleştirme katmanı.
4. **Sensörler:** eBPF (Tracee) birincil; `strace -f -y` yedek. Dosya sistemi için overlayfs upper-diff; ağ için ayrı netns + tcpdump/mitmproxy; süreç ağacı için cgroup.
5. **Probe çalıştırma:** Şemadan türetilen deterministik çağrılar — her araç için: normal girdi, sınır girdisi (`/etc/passwd`, `../../`, `http://example.com`, çok büyük payload, env değişkeni adı). v1'de LLM üretimi yok; v2'de opsiyonel.
6. **Normalizasyon:** Ham olaylar → Event şeması; dedup; capability çıkarımı (yol → glob, host → domain).
7. **Diff:** `observed - declared` → Finding üret. Şiddet kuralları aşağıda.
8. **Çıktı:** Manifest + JSON/Markdown rapor + **önerilen politika taslağı** (`policy.suggested.yaml`).

### 5.1 Finding şiddet kuralları

| Bulgu | Şiddet |
|---|---|
| Bildirilmemiş dış ağ (`net.egress`) | Yüksek |
| Bildirilmemiş kök dışı dosya okuma | Yüksek |
| Gizli anahtar / kimlik dosyası okuma (`~/.ssh`, `~/.aws`, `.env`) | Kritik |
| Alt süreç / kabuk doğurma | Orta–Yüksek |
| Dinamik kod yükleme (`eval`, `exec`, `pickle`) | Orta |
| Workspace dışına yazma | Yüksek |
| Sadece bildirileni yapıyor | Bilgi |

### 5.2 Sandbox sertleştirme

```
docker run --rm \
  --network none \                # egress yalnızca izinli proxy üzerinden
  --read-only --tmpfs /tmp:size=64m \
  --user 65534:65534 \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 512m --cpus 1 \
  --runtime=runsc                 # gVisor (varsa), yoksa runc
```

- Docker socket **asla** mount edilmez.
- Egress allowlist: yalnızca probe sırasında açıkça izin verilen host'lar.
- Ana makinede asla çalıştırılmaz; ayrı VM ikinci savunma hattı.

---

## 6. Runtime plane — çağrı başına akış

```
tool_call
   │
   ├─1. Parse & capability çıkarımı        (~1 ms)
   ├─2. Provenance/taint çözümlemesi        (~5–20 ms, cache'li)
   ├─3. Politika değerlendirmesi            (~1–2 ms)
   ├─4. Karar
   │     allow ─────────────► araç çağrısı
   │     deny ──────────────► hata + UI
   │     approve ───────────► onay akışı (timeout = deny)
   │     constrain ─────────► argüman yeniden yazımı
   ├─5. Sonuç filtreleme (sır redaksiyonu)
   └─6. Olay kaydı (hash-chain)
```

**Hedef gecikme:** p50 < 10 ms, p95 < 100 ms. Bu sayı README'de ölçülür.

### 6.1 `constrain` kararları (projenin pratik zekâsı)

Her şeyi reddetmek ürünü kullanılamaz yapar. Yumuşak müdahaleler:

- URL'yi allowlist'e göre yeniden yaz / host'u maskele.
- Dosya yolunu workspace köküne hapset (`realpath` + prefix kontrolü).
- Kabuk komutunu kısıtlı argüman setine indir.
- Araç çıktısındaki sırları redakte et (JSON anahtarı + değer kalıpları).

---

## 7. Taint / bilgi akışı — zor çekirdek

Modelin içini göremiyoruz. Bu yüzden iki katmanlı bir yaklaşım:

### Katman A — IFC kapısı (sağlam, provenance'dan bağımsız)

Oturuma **güven etiketi** eklenir. Bir kez `untrusted_web` etiketi girdiyse, oturum "kirli" sayılır ve yüksek riskli yetenek sınıfları kısıtlanır:

- `secret.read` → deny
- `net.egress` (allowlist dışı) → approve
- `fs.write` (workspace dışı) → deny

Temizleme (declassification) yalnızca **kullanıcı onayıyla** veya oturum sonunda olur. Bu katman, taint'i tam bilemesek de lethal trifecta'yı keser.

### Katman B — Provenance sezgisi (hassas, açıklanabilir)

Proxy, gördüğü her içerik parçasını (`context_inject`: tool sonucu, fetch edilen sayfa, dosya içeriği) etiketler. Giden tool argümanı bu parçalarla karşılaştırılır:

- Normalize + whitespace sadeleştirme + shingle (n=8 token) eşleşmesi.
- v2: embedding benzerliği (opsiyonel, `pgvector`).
- Eşleşme varsa `provenance` alanına `segment_id` yazılır; UI zinciri gösterir: **sayfa → tool sonucu → tool çağrısı → kural**.

**Dürüst sınır:** Katman B yanlış negatif verebilir (model içeriği yeniden yazarsa). README'de açıkça yazılır ve ölçülür (FP/FN tablosu). Katman A, B başarısız olduğunda hâlâ korur. Bu, mülakatta "farkındasın" sinyali veren türden bir tasarım kararı.

---

## 8. Politika DSL

YAML, sürümlenmiş, deterministik, deny-overrides.

```yaml
version: 1
defaults:
  decision: deny
  approval_timeout: deny
  on_error: deny

rules:
  - id: fs-workspace-only
    when:
      capability: fs.read
      not: { path.within: "${workspace}" }
    then: deny
    reason: "Workspace dışı okuma"

  - id: secrets-guard
    when:
      any:
        - path.matches: "**/.ssh/**"
        - path.matches: "**/.aws/**"
        - path.matches: "**/.env"
    then: deny
    reason: "Kimlik bilgisi dosyası"

  - id: lethal-trifecta
    when:
      session.tainted_with: untrusted_web
      capability: net.egress
      not: { host.in: "${allowlist}" }
    then: approve
    reason: "Güvenilmeyen içerik sonrası dış ağ çağrısı"

  - id: shell-allowlist
    when:
      capability: proc.exec
      not: { command.in_allowlist: true }
    then: deny

  - id: redact-secrets
    when: { capability: fs.read }
    then: constrain
    action: redact_patterns: ["AKIA[0-9A-Z]{16}", "sk-[A-Za-z0-9]{20,}"]
```

Değerlendirme deterministik: yetkilendirme sırası `deny` > `approve` > `allow`; eşitlikte `rule_id` alfabetik. **`then: constrain` yetki vermez** — eşleşen kısıtları kazanan `allow`/`approve` kararına ekler. Bu ayrım, "çıktıdaki sırları redakte et" gibi yatay kuralların yetkilendirmeyi gölgelemesini engeller. `policy test` komutu, kaydedilmiş olay setine karşı politika değişikliklerinin farkını üretir.

---

## 9. Depolama ve replay

- **SQLite (WAL):** oturumlar, olaylar, manifestler, politikalar.
- **JSONL append-only log:** her satır `prev_hash` içerir (hash-chain). Kurcalama tespit edilebilir.
- **Replay:** `agentgate replay <session> --policy v2` → aynı olaylar yeni politikayla değerlendirilir; "eski politika allow, yeni politika deny" farkı tablo olarak çıkar.
- Replay, hem demo hem regresyon testi hem de `policy test` altyapısıdır.

---

## 10. UI (demo burada kazanılır)

Üç ekran yeter:

1. **Session Timeline:** solda ajan/araç olayları, sağda karar rozetleri; engellenen çağrı kırmızı, zinciri tıklanabilir.
2. **Attack Graph:** içerik kaynağı → ajan → tool → hedef düğümleri; engellenen kenar kesik çizgi.
3. **Policy Studio:** YAML editörü + kaydedilmiş oturum üzerinde anlık "şu an ne olurdu" önizlemesi.

V1'de yalnızca timeline gerekli; graf ikinci ay.

---

## 11. Depo yapısı

```
agentgate/
├── core/           # şemalar, policy engine, taint, risk
├── proxy/          # MCP stdio/http, session, hooks
├── inspector/      # sandbox, sensors, probes, normalizer
├── store/          # sqlite, hash-chain, replay
├── api/            # fastapi, ws
├── ui/             # react + ts
├── cli/            # typer
├── adapters/       # langchain, claude-code, generic
├── policies/       # örnek politikalar
├── benchmarks/     # 10 MCP sunucusu, injection corpus
├── tests/
└── docs/
```

---

## 12. Yol haritası (haftada 10–15 saat)

| Hafta | Hedef | Bitti sayılır |
|---|---|---|
| 1–3 | **V1 — Proxy + allowlist** | stdio MCP proxy, YAML politika, audit log, `deny` çalışıyor, 2 dk demo |
| 4–6 | **V2 — Inspector** | Docker sandbox, fs/net/exec kaydı, declared⇄observed diff, rapor |
| 7–10 | **V3 — IFC + onay** | taint katmanı, lethal-trifecta, onay akışı, timeline UI |
| 11–14 | **V4 — Replay + ölçüm** | replay, `policy test`, 10 MCP sunucusu benchmark, latency tablosu |
| 15–18 | **V5 — Cila** | attack graph, redaksiyon, README + blog + demo videosu |
| 19–24 | **Stretch** | eBPF sensör, gVisor, politika önerisi (manifest→policy), çoklu oturum |

Her aşamanın sonunda **çalışan bir demo** ve **bir metrik** var. Bu, 3. ayda "yarım sistem" hissini önler.

---

## 13. Metrikler (CV'ye giden sayılar)

- **Denetim:** 10 popüler MCP sunucusunda bildirilmemiş yetenek oranı; manuel doğrulanmış bulgu precision'ı.
- **Engelleme:** prompt injection korpusunda saldırı başarı oranı (ASR) önce/sonra; 100 temiz oturumda yanlış ret oranı.
- **Performans:** çağrı başına ek yük p50/p95; saniyedeki karar sayısı.
- **Replay:** 1000 olayda determinizm oranı (%100 hedef).
- **Kapsam:** desteklenen taşıma (stdio/HTTP) ve adaptör sayısı.

---

## 14. Riskler ve yapılmayacaklar

**Riskler:** sandbox kaçışı (gVisor + ayrı VM), taint yanlış negatifi (Katman A yedeği), MCP spesifikasyon değişimi (adaptör izolasyonu), kapsam kayması (her ay tek hedef).

**Non-goals:** malware analiz sandbox'ı değil; kurumsal DLP değil; model jailbreak savunması değil; host EDR değil. README'de bunlar yazılı olacak — olgunluk göstergesi.

**Etik/yetki:** yalnızca sahip olunan veya açık kaynak MCP sunucuları, izole ortamda. Üretim sistemine yönelik kullanım yok. Test kapsamı README'de.

---

## 15. Mülakat anlatısı (30 saniye)

> "Ajanların araç çağrılarını iki taraftan denetleyen bir katman yazdım. Çalıştırmadan önce, Docker sandbox'ta araç sunucusunu koşup gerçekte ne yaptığını syscall ve ağ düzeyinde kaydediyorum; tanıtımında yazanla karşılaştırıp manifest üretiyorum. Çalışma anında ise MCP proxy her çağrıyı kesiyor; içerik kaynağını izleyip politika uyguluyorum. 10 popüler MCP sunucusunda X tanesinde bildirilmemiş ağ erişimi buldum; injection korpusunda saldırı başarı oranını %Y'den %Z'ye düşürdüm, p95 ek yük W ms."

Sayıları sen dolduruyorsun; cümle kalıbı hazır.
