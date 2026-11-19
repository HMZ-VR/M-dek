-- 010_student_email_format.sql
-- Mevcut öğrenci hesaplarını okul standardına taşır:
--   e-posta    : f<öğrenci_no>@ktun.edu.tr   (önceki: <no>@ogrenci.edu.tr)
--   kullanıcı  : f<öğrenci_no>               (önceki: <no>)
-- Kullanıcı adı = e-postanın yerel kısmı (instructor akışıyla aynı desen).
--
-- İdempotent: zaten 'f'/'F' ile başlayan kullanıcı adları atlanır, böylece
-- migration her deploy'da yeniden çalışsa da çift-f oluşmaz ve veri değişmez.
-- student_no'su olmayan öğrenciler (örn. elle açılmış, numarasız) dışlanır.

-- Not: PostgreSQL UPDATE...FROM içinde hedef tablo (u) yalnızca WHERE'den
-- referans alınabilir; bu yüzden ek tablolar comma-FROM ile listelenir ve
-- tüm join koşulları WHERE'e taşınır.
UPDATE users u
SET email    = 'f' || s.student_no || '@ktun.edu.tr',
    username = 'f' || s.student_no
FROM students s, user_roles ur, roles r
WHERE s.user_id   = u.id
  AND ur.user_id  = u.id
  AND r.id        = ur.role_id
  AND r.code      = 'student'
  AND s.student_no IS NOT NULL
  AND s.student_no <> ''
  AND u.username !~ '^[fF]';
