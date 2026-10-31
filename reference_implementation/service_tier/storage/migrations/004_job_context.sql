-- Job kalemleri satıcı ve işletim sistemi bilgisini taşır.
--
-- Bu alanlar belirsiz ürün adlarını ("Calendar") çözmek için gereklidir;
-- kuyruğa alınan istekte kaybolurlarsa worker taramayı eksik bilgiyle yapar.

ALTER TABLE job_items ADD COLUMN IF NOT EXISTS vendor           TEXT NOT NULL DEFAULT '';
ALTER TABLE job_items ADD COLUMN IF NOT EXISTS operating_system TEXT NOT NULL DEFAULT '';
