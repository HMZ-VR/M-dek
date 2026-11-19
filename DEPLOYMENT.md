# Mudek Production Deployment Guide

This document describes how to deploy the Mudek system for real-world
university use. Follow every step; the API now refuses to start with a
default `SECRET_KEY` or weak configuration.

## 1. Server prerequisites

- Ubuntu 22.04+ (or any Linux with Docker 24+ and docker compose v2)
- PostgreSQL 13+ reachable from the API container (external or via
  `host.docker.internal` in single-host setups)
- A DNS record pointing `mudek.ktun.edu.tr` (or your real hostname) at the
  server
- Ports 80 and 443 open

## 2. Configure `.env`

```
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(64))"  # generate SECRET_KEY
```

Edit `.env` and set:

- `DATABASE_URL` — production Postgres DSN
- `SECRET_KEY` — the 64-byte URL-safe string from the command above
- `CORS_ORIGINS` — the public HTTPS origin only (e.g. `https://mudek.ktun.edu.tr`).
  Using `*` is only acceptable on a private staging network.
- `PUBLIC_BASE_URL` — the public HTTPS origin (same as above). Used to build the
  links inside password-reset emails so they point at the live site.
- `LOGIN_RATE_LIMIT_PER_MINUTE` — keep default `10` unless you have a specific reason
- `ENVIRONMENT=production`
- SMTP settings (for the self-service "Şifremi Unuttum" flow): `SMTP_HOST`,
  `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS`
  (or `SMTP_SSL=true` for port 465). Use the institution's mail relay.
  **If `SMTP_HOST` is left empty**, password-reset emails are simply not sent —
  the page still works and admins can reset passwords from the user panel as a
  fallback (see §6). Self-service reset starts working as soon as SMTP is set.

`.env` is gitignored. **If `git status` ever shows `.env` as tracked**, untrack it
and rotate the key:

```bash
git rm --cached .env          # stops tracking; file stays on disk
# then regenerate SECRET_KEY (above) so the previously-committed key is dead
```

Never commit the real `.env`.

## 3. Enable HTTPS (mandatory before go-live)

HTTP-only deployments leak JWTs and passwords on the wire. Do one of:

### 3a. Let's Encrypt with certbot (recommended)

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d mudek.ktun.edu.tr
# → creates /etc/letsencrypt/live/mudek.ktun.edu.tr/fullchain.pem + privkey.pem
```

Mount the certs into the web container. Edit `docker-compose.yml` `web` service:

```yaml
  web:
    image: nginx:1.27
    container_name: mudek_web
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./web:/usr/share/nginx/html:ro
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./nginx/rate-limit.conf:/etc/nginx/conf.d/00-rate-limit.conf:ro
      - /etc/letsencrypt/live/mudek.ktun.edu.tr:/etc/ssl/mudek:ro
    depends_on:
      - api
    restart: unless-stopped
```

Then replace the HTTP config with the HTTPS template:

```bash
cp nginx/default.https.conf.example nginx/default.conf
docker compose up -d --force-recreate web
```

Automate renewal:

```cron
0 4 * * 1 certbot renew --quiet --deploy-hook "docker compose -f /opt/mudek/docker-compose.yml restart web"
```

### 3b. Behind an existing TLS terminator

If the institution already terminates TLS (e.g., at a load balancer),
keep nginx on HTTP internally and make sure `X-Forwarded-Proto` is
forwarded. Set `CORS_ORIGINS=https://mudek.ktun.edu.tr`.

## 4. Run database migrations (mandatory on first install and after every update)

The schema is managed by the migration chain in `scripts/migrations/`. The
migrations are idempotent — re-running the chain on an up-to-date database is
a no-op, so run it on first install **and** after every `git pull`.

Primary method (no extra tools needed; runs inside the api image):

```bash
docker compose build
docker compose run --rm api python scripts/run_migrations.py
```

Alternative from the host (requires `psql`: `sudo apt install postgresql-client`):

```bash
# NOTE: host.docker.internal only resolves inside containers. When running
# from the host, point DATABASE_URL at localhost (or the real DB host).
DATABASE_URL='postgresql://USER:PASS@localhost:5432/mudek_db' \
    bash scripts/run_migrations.sh
```

## 5. Build and launch

```bash
mkdir -p uploads   # bind-mounted to /data/uploads; create it before first start
docker compose build
docker compose up -d
docker compose logs -f api   # verify "Application startup complete"
curl -fsS http://localhost/health
```

On Linux servers, if uploads fail with "Permission denied", give the
container user ownership of the bind mount:

```bash
sudo chown -R "$(docker compose exec api id -u):$(docker compose exec api id -g)" uploads
```

Smoke-test auth gates:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" https://mudek.ktun.edu.tr/api/courses  # expect 401
```

## 6. Create the first admin user

The API does not ship with seed credentials. Create one via SQL:

```sql
INSERT INTO users (username, password_hash, full_name, email, is_active, must_change_password)
VALUES ('admin',
        '$2b$12$REPLACE_WITH_BCRYPT_HASH',
        'System Admin',
        'admin@ktun.edu.tr',
        TRUE,
        TRUE);

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r WHERE u.username='admin' AND r.code='admin';
```

Generate the bcrypt hash offline:

```bash
docker compose exec api python -c "import bcrypt; print(bcrypt.hashpw(b'STRONG-INITIAL-PASSWORD', bcrypt.gensalt(rounds=12)).decode())"
```

The admin must change the password on first login (`must_change_password=TRUE`).

### 6b. Demo / presentation data

For a demo you can populate a realistic dataset
with `scripts/seed_demo_data.sql` (3 courses, offerings, exams, surveys and a
sample committee report). It assumes 20 demo students (`student_no` `2026xxx`)
already exist — create them via the student upload UI first, or run the demo on
the machine where they already exist.

**Before real production use, remove demo data** so it does not mix with real
records:

```bash
docker compose exec -T api python -c "
import os, psycopg
with psycopg.connect(os.environ['DATABASE_URL']) as c:
    c.execute(open('scripts/clear_demo_data.sql').read()); c.commit()
"
```

The cleanest production database starts with **no demo data at all** — just the
admin user from §6.

## 7. Nightly database backups

```bash
sudo cp scripts/backup_db.sh /opt/mudek/scripts/
sudo crontab -e
# add:
0 3 * * * /opt/mudek/scripts/backup_db.sh >> /var/log/mudek-backup.log 2>&1
```

Backups land in `./backups/` by default. Override with `BACKUP_DIR=/var/backups/mudek`.
They are gzip'd SQL dumps; keep 14 days (configurable via `BACKUP_RETAIN_DAYS`).

Test a restore on a staging DB quarterly.

## 8. Security checklist (must pass before go-live)

- [ ] Migrations applied: `docker compose run --rm api python scripts/run_migrations.py` ends with "✅"
- [ ] `SECRET_KEY` is the 64-byte random value, not the default
- [ ] `.env` is not committed (`git status` shows it untracked)
- [ ] `CORS_ORIGINS` and `PUBLIC_BASE_URL` are the production origin only
- [ ] HTTPS reaches the browser (check SSL Labs grade ≥ A)
- [ ] API port `8000` is **not** published to the host (only nginx 80/443 are);
      `docker compose ps` should show no host port for the `api` service
- [ ] `GET /api/courses` without a token returns 401
- [ ] `DELETE /api/courses/1` as a student returns 403
- [ ] First admin logs in, is forced to change password, flag clears
- [ ] Password reset: `forgot-password.html` → email arrives → `reset-password.html`
      sets a new password and the old session is invalidated. (If SMTP is left
      unconfigured on purpose, confirm admins know to reset via the user panel.)
- [ ] Demo data removed (`scripts/clear_demo_data.sql`) if it was ever loaded
- [ ] Backup script ran at least once and produced a valid `.sql.gz`
- [ ] `audit_log` table has entries for recent mutations:
      `SELECT ts, user_id, action, status_code FROM audit_log ORDER BY ts DESC LIMIT 20;`

## 9. Operational runbook

### Check API health
```
curl -fsS https://mudek.ktun.edu.tr/health
```

### View live API logs
```
docker compose logs -f api
```

### Inspect recent auth failures
```sql
SELECT ts, ip, username, action, status_code
FROM audit_log
WHERE action LIKE 'login.%' OR status_code IN (401, 403, 429)
ORDER BY ts DESC LIMIT 50;
```

### Rotate SECRET_KEY
1. Generate a new key with `python3 -c "import secrets; print(secrets.token_urlsafe(64))"`
2. Update `SECRET_KEY` in `.env`
3. `docker compose restart api`
4. All existing JWTs are invalidated — users must log in again (expected).

### Force all users to change password
```sql
UPDATE users SET must_change_password = TRUE WHERE username NOT IN ('admin');
```

## 10. Known limitations (acceptable for initial launch)

- No pagination on large list endpoints — tolerable at current user scale
  (sub-10k users). Monitor query times in `access log` middleware.
- Monolithic `api/main.py`. Splitting into routers is a low-risk future
  refactor but not required for security.
- In-memory login rate limiter — resets on restart. For multi-node
  deployments, put a rate-limit layer at nginx or add Redis later.
