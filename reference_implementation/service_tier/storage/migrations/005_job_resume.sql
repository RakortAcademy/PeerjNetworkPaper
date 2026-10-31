-- Job'ların yeniden başlatmadan sonra kaldığı yerden devam etmesi.
--
-- `attempts`: bir job kaç kez alındı. Süreç çökerse ya da geçici bir hata
-- (veritabanı bağlantısı, model yüklemesi) job'ı yarıda keserse job kalıcı
-- olarak FAILED işaretlenmemeli — kalan kalemlerle yeniden denenmeli. Sayaç
-- sonsuz döngüyü engeller: üst sınıra ulaşan job FAILED olur.
--
-- `heartbeat_at`: RUNNING bir job'ın son yaşam işareti. Süreç SIGKILL ile
-- ölürse durum RUNNING'de kalır; açılışta bu job'lar kuyruğa geri alınır.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS attempts     INTEGER     NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;

-- Kaldığı yerden devam ederken bekleyen kalemleri bulmak sık yapılan sorgudur.
CREATE INDEX IF NOT EXISTS job_items_pending_idx
    ON job_items (job_id, position)
 WHERE result IS NULL AND error IS NULL;
