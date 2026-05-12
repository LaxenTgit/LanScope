# 🐳 LanScope Docker

LanScope'u Docker container içinde çalıştırma rehberi.

&gt; ⚠️ **Önemli:** LAN tarama için `--network host` ve `--privileged` gerekli!

---

## Hızlı Başlangıç

```bash
# 1. Repo'ya git
cd LanScope

# 2. Output dizini oluştur
mkdir -p output

# 3. Varsayılan servisi çalıştır (tam tarama)
docker-compose -f docker/docker-compose.yml --profile default up

# 4. Sonuçları kontrol et
ls output/
# scan_20240115_143022.json
