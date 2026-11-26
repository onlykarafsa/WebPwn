# WebPwn

WebPwn, Python 3.10+ ile çalışan, tek dosyalı ve yetkili web güvenlik değerlendirme aracıdır. HTTP Repeater, temel güvenlik yapılandırması kontrolleri, kontrollü kaynak keşfi ve isteğe bağlı düşük etkili parametre yansıması kontrolü sunar.

> **Yasal kullanım:** Yalnızca sahibi olduğunuz veya test etmek için açık ve geçerli izniniz bulunan sistemlerde kullanın. `--authorized` seçeneği yalnızca kullanıcının yetki beyanıdır; gerçek izin yerine geçmez.

## Özellikler

- Tek dosya: `webpwn.py`
- HTTP Repeater: GET/HEAD istekleri, özel header'lar, yanıt görüntüleme ve geçmiş
- Scope kilidi: şema + ana makine + port eşleşmesi; wildcard ve scope dışı yönlendirmeler reddedilir
- İstek sayısı sınırı, istekler arası bekleme, timeout ve yanıt boyutu sınırı
- TLS sertifika doğrulaması açık
- Güvenlik başlıkları ve cookie bayrakları kontrolleri
- Genel hata sayfalarını ayırt etmeye yardımcı kontrol yanıtı karşılaştırması
- İsteğe bağlı düşük etkili parametre yansıması kontrolü
- JSON ve Markdown raporları
- Yerel demo sunucusu ve dahili testler

## Gereksinimler

- Python 3.10 veya üzeri
- Harici Python paketi gerekmez (Python standart kütüphanesi kullanılır)

## Hızlı başlangıç

### 1. Testleri çalıştır

```bash
python webpwn.py self-test
```

### 2. Yerel demo sunucusunu başlat

```bash
python webpwn.py demo
```

Demo sunucusu yalnızca `127.0.0.1:8000` üzerinde dinler. Bu terminal açık kalsın.

### 3. İkinci terminalde yerel demo'yu tara

```bash
python webpwn.py scan http://127.0.0.1:8000 --authorized --active-safe
```

Raporlar `webpwn-report.json` ve `webpwn-report.md` olarak oluşturulur.

## Repeater kullanımı

Yalnızca kendi yerel demo sunucunuzda:

```bash
python webpwn.py repeater http://127.0.0.1:8000 --authorized
```

Repeater içindeki komutlar:

| Komut | Açıklama |
|---|---|
| `send` | Seçili GET/HEAD isteğini gönderir |
| `url` | Aynı origin içindeki URL veya yolu değiştirir |
| `method` | GET veya HEAD seçer |
| `header` | Özel header ekler/değiştirir |
| `headers` | Özel header listesini gösterir |
| `history` | Önceki istekleri listeler |
| `save` | Son yanıt gövdesini dosyaya kaydeder |
| `help` | Komut yardımını gösterir |
| `quit` | Repeater'dan çıkar |

## Yetkili hedef taraması

Tam URL girin ve yalnızca test izniniz olan origin'i hedefleyin:

```bash
python webpwn.py scan https://staging.example.org --authorized --max-requests 30 --delay-ms 300
```

Düşük etkili parametre yansıması kontrolünü ayrıca etkinleştirmek için `--active-safe` ekleyin. Bu kontrol tek başına XSS kanıtı değildir. SQL enjeksiyonu, RCE, dosya okuma veya webshell istismarı yapmaz.

## Güvenlik sınırları

Bu sürüm yalnızca GET/HEAD istekleri gönderir. POST/PUT/DELETE, kimlik bilgisi saldırıları, veri çıkarma, dosya yükleme/okuma, komut çalıştırma, webshell, yıkıcı payload, WAF atlatma veya gizlenme özellikleri içermez. Aktif kontrol seçeneği düşük etkili parametre yansıması kontrolüyle sınırlıdır.

## Proje yapısı

```text
WebPwn/
├── webpwn.py       # Uygulamanın tamamı
├── README.md       # Kurulum ve kullanım
├── LICENSE         # MIT lisansı
├── SECURITY.md     # Güvenli kullanım ve bildirim
├── CONTRIBUTING.md # Katkı yönergeleri
├── .gitignore
└── requirements.txt
```

## Lisans

MIT. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
