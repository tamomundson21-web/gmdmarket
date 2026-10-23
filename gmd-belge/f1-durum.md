# F1 Durum Raporu — GMD Market

**Tarih:** 2026-10-23
**Kapsam:** F1 (auth/rol/grup, kayıt/onay, oturum, profil yetkileri)

## Tamamlanan ve gerçek test edilen

| Alan | Durum | Kanıt |
|---|---|---|
| DB şeması (11 tablo + TC vault) | ✅ | migration 0001–0003 uygulandı, `\dt` doğrulandı |
| F1-C01..C06 kısıtları (UNIQUE/FK/CHECK) | ✅ | migration'da tanımlı, ihlallerde DB reddi |
| argon2 0.45.1 (v=19, m=19456, t=2, p=1) | ✅ | hash/verify test edildi |
| Envelope (HMAC-SHA256, 15 dk pencere) | ✅ | oluşturma + expiry testi |
| Kayıt (kodsuz → pending / davetli → approved) | ✅ | canlı test |
| Master onay (approved + ilk 0 USD hesap) | ✅ | canlı test, `accounts.balance=0.00` |
| Idempotency (aynı command_key → özgün sonuç) | ✅ | canlı test |
| Login + argon2 doğrulama | ✅ | doğru/yanlış parola testi |
| Oturum aileleri (max 2, LRU iptal) | ✅ | 3 login → 2 aile, en eski 401 |
| remember_me (30 gün grant) | ✅ | cookie + grant kaydı |
| Logout (aile iptali) | ✅ | sonrası /v1/me 401 |
| Şifre değişimi (diğer aileleri iptal) | ✅ | canlı test |
| Reset token (1 saat, tek kullanım) | ✅ | üretim + tüketim |
| T.C. AES-256-GCM şifreli kasa (O07) | ✅ | master KV1 okuma decrypt etti |
| CSRF + Origin kontrolü | ✅ | Origin yok → 403 |
| Admin: müşteri oluşturma / karar / e-posta | ✅ | karar testi geçti |

## Henüz AÇIK teknik kapılar (sözleşme gereği)

Bunlar "yapılmadı" değil, **gerçek ortam/ölçüm kanıtı** gerektiren kapılardır:

- **EP1 tam uyum:** Unicode17/IDNA UTS#46 normalizasyonu, tam mailbox parser, `email-v1-u17` profili. Şu an basitleştirilmiş lower+trim uygulanıyor.
- **JCS/numbers-free codec:** kanonik JSON + HMAC profili (şu an JSON.stringify benzeri). Sözleşme "JSON.stringify yeterli değil" diyor.
- **Browser context / bootstrap / proof cookie:** `__Host-tp-b-` proof, context_id taşıma. Şu an yok.
- **CSRF seed tam modeli:** scope/binding_kind/head_revision ile ayrı digest.
- **Constraint trigger (DEFERRABLE):** F1-C02/C03 işlem-sonu çapraz kontrolleri (şu an CHECK + FK var, trigger yok).
- **Advisory lock sırası:** `f1-user-lock-v1` fiziksel key sıralaması.
- **R10 retention_anchor:** gerçek COMMIT gözlemi + 24 saat GC.
- **Parola 128 scalar üst sınırı:** request-byte/native uyumu.
- **Gerçek tarayıcı testleri:** Set-Cookie yarışı, BFCache, PWA, WebSocket bind.
- **HS (hesap silme) yolları:** T10/T11 kapısı.
- **Davet (desk_invites) uçtan uca:** tablo var, oluşturma akışı yok.

## Komutlar

```bash
# Migration
docker exec -i gmd-db psql -U gmd -d gmd < infra/migrations/0001_bootstrap.sql
docker exec -i gmd-db psql -U gmd -d gmd < infra/migrations/0002_f1_auth_schema.sql
docker exec -i gmd-db psql -U gmd -d gmd < infra/migrations/0003_tc_identity_vault.sql

# Master seed (dev)
cd apps/api && DATABASE_URL=... npx tsx src/seed.ts

# Dev sunucu
DATABASE_URL=... npx tsx src/server.ts
```

## Sınır beyanı

Bu, F1'in **çalışan çekirdeğidir**; sözleşmenin "tamamlandı" sayılması için
yukarıdaki açık kapıların gerçek test kanıtı gerekir. A grubu (A01/A02/A20)
testleri henüz ÇALIŞTIRILMADI.
