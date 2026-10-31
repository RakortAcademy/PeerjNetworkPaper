-- Model çıkarımlarının kalıcı önbelleği.
--
-- Bir CVE'nin ürün/sürüm çıkarımı YALNIZCA açıklama metnine ve model sürümüne
-- bağlıdır — taranan müşteri sürümüyle hiç ilgisi yoktur. Buna rağmen her yeni
-- sürüm sorgusunda (1.0.0 tarandıktan sonra 1.1.0) aynı CVE'ler modelden
-- yeniden geçiyordu. Paylaşım yalnızca TEK istek içinde çalışıyordu.
--
-- Bu tabloyla model her CVE için ömründe bir kez çalışır; sonraki tüm taramalar
-- — hangi üründen, hangi sürümden gelirse gelsin — hazır çıkarımı okur.
--
-- description_hash: açıklama güncellenirse (CVE revize edilir) önbellek kaydı
-- geçersiz sayılsın diye tutulur; eşleşmeyen kayıt yokmuş gibi davranılır.

CREATE TABLE IF NOT EXISTS cve_extractions (
    cve_id           TEXT        NOT NULL,
    model_version    TEXT        NOT NULL,
    description_hash TEXT        NOT NULL,
    payload          JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, model_version)
);

-- Eski model sürümlerinin kayıtlarını toplu silmek için.
CREATE INDEX IF NOT EXISTS cve_extractions_model_idx
    ON cve_extractions (model_version);
