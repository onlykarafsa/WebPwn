# Katkıda Bulunma

1. Değişiklik için ayrı bir branch oluşturun.
2. Kodun Python 3.10+ ile uyumlu kalmasını sağlayın.
3. Güvenlik sınırlarını (yalnızca GET/HEAD, origin kilidi, istek bütçesi ve TLS doğrulaması) gevşetmeyin.
4. Yeni davranışlar için test ekleyin.
5. Pull request öncesinde şu komutu çalıştırın:

```bash
python webpwn.py self-test
```

İzinsiz erişim, veri çıkarma, kimlik bilgisi saldırısı, webshell veya güvenlik kontrollerini atlatma işlevleri kabul edilmez.
