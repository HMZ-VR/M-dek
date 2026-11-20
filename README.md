# MÜDEK Accreditation Management System

A web platform that helps engineering departments run the **MÜDEK** accreditation process (Turkey's engineering accreditation body, a signatory of the Washington Accord). It tracks how well students reach each **course learning outcome (DÖÇ)** and **program outcome (PÇ)**. It works from raw exam scores, surveys and committee reports, and produces the reports an accreditation review asks for.

The data model follows the standard MÜDEK course-evaluation spreadsheet, so other departments can adapt it.

## Background

The Dean of the Faculty of Engineering and Natural Sciences at Konya Technical University (KTUN) gave me this project while I was an undergraduate there. The goal was a system that would help the faculty prepare for MÜDEK accreditation.

Accreditation reviewers ask for evidence that each course contributes to the program outcomes, and that the department acts on the results. Departments usually collect this evidence in large, hand-maintained Excel workbooks. This system replaces those workbooks with one shared web application. Instructors enter scores once, and the system calculates outcome achievement, tracks trends across terms, and produces the reports, committee documents and evidence an accreditation review needs.

### My role

I designed and built the whole system on my own, working with the Dean on the requirements:

- **Domain modelling:** turned the official MÜDEK course-evaluation spreadsheet, and its formulas, into a relational schema and a tested calculation engine
- **Backend:** a FastAPI REST API with about 110 endpoints, role-based permissions, PDF and Excel generation, and a versioned migration chain
- **Frontend:** about 40 pages, including role-specific dashboards, a student portal and reporting screens
- **Security & operations:** authentication hardening, rate limiting, audit logging, a Docker and nginx deployment, HTTPS and backups

> This project is not an official product of MÜDEK or KTUN.

---

## Features

**Outcome-based assessment**
- Define courses, course offerings (term and section) and their learning outcomes (DÖÇ)
- Map exam questions to learning outcomes with weights, and learning outcomes to the program outcomes (PÇ-1 … PÇ-11)
- Calculations match the official MÜDEK Excel template formula for formula: weighted DÖÇ and PÇ achievement, midterm / final / make-up exam rules, a passing-students-only filter and relative letter grading
- Exams with a project component (configurable project weight)
- Bulk score upload from Excel

**Reporting & continuous improvement**
- Course performance reports with DÖÇ and PÇ breakdowns and Excel export
- Program outcome trend reports across terms (the PDCA / PUKÖ improvement loop)
- Per-student competency portfolio with a per-course DÖÇ and PÇ breakdown
- Instructor reflections and action plans for each exam and offering
- Upload "best / average / worst" sample exam papers as accreditation evidence

**Committees & surveys**
- Committees with members, a report submit → review → approve workflow, and PDF output
- Student surveys tied to program outcomes, with results dashboards

**Security**
- Role-based access control with seven roles: Admin, Head of Department, Faculty Member, Research Assistant, Committee Member, MÜDEK Board Member and Student
- bcrypt password hashing, JWT auth with token revocation, and a forced password change on first login
- Self-service password reset over SMTP, using hashed single-use tokens
- Login rate limiting, an audit log, nginx security headers and rate limits
- The API refuses to start with a missing or weak `SECRET_KEY`

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3 · FastAPI · psycopg 3 (connection pool) · pandas / openpyxl · ReportLab |
| Database | PostgreSQL 13+ |
| Frontend | Static HTML / CSS / vanilla JS served by nginx (jsPDF for client-side PDFs) |
| Infrastructure | Docker Compose · nginx 1.27 · MailHog for local email testing |
| Tests | pytest |

## Project structure

```
api/                 FastAPI application
  main.py            REST endpoints
  mudek_service.py   DÖÇ / PÇ calculation engine
  auth_utils.py      JWT, bcrypt, role & permission checks
  security_ext.py    Rate limiting, token revocation, audit log
  password_reset.py  Self-service password reset
  committee_pdf.py   Committee report PDF generation
  tests/             Unit tests for the calculation engine
web/                 Frontend pages (dashboard, reports, portals, …)
nginx/               nginx configs (HTTP, HTTPS example, rate limits)
scripts/
  migrations/        Ordered, idempotent SQL / Python schema migrations
  run_migrations.py  Migration runner
  seed_demo_data.sql Optional demo dataset
  backup_db.sh       Database backup helper
docker-compose.yml   Production services (api + nginx)
DEPLOYMENT.md        Full production deployment guide
```

---

## Getting started (local)

**Prerequisites:** Docker with Compose v2, and a PostgreSQL server the API container can reach.

1. **Create the database and configuration**

   ```bash
   createdb mudek_db
   cp .env.example .env
   python3 -c "import secrets; print(secrets.token_urlsafe(64))"   # paste as SECRET_KEY
   ```

   In `.env`, set `DATABASE_URL`. For example, `postgresql://USER:PASSWORD@host.docker.internal:5432/mudek_db` points at Postgres running on the host. Also set `CORS_ORIGINS=http://localhost:8080`.

2. **Build and run the migrations**

   ```bash
   docker compose build
   docker compose run --rm api python scripts/run_migrations.py
   ```

3. **Start the stack**

   ```bash
   mkdir -p uploads
   docker compose up -d
   curl -fsS http://localhost/health    # → {"ok":true}
   ```

   The local `docker-compose.override.yml` also exposes:
   - the web app at <http://localhost:8080>
   - the API and Swagger docs at <http://localhost:8000/docs>
   - the MailHog inbox (captured password-reset emails) at <http://localhost:8025>

4. **Create the first admin.** No default credentials ship with the app. Follow [DEPLOYMENT.md § 6](DEPLOYMENT.md#6-create-the-first-admin-user) to create an admin user with a bcrypt-hashed password, then sign in at `/login.html`.

5. **(Optional) Load demo data:** `scripts/seed_demo_data.sql` creates 3 courses over 2 terms, with exams, responses, surveys and a committee report. See [DEPLOYMENT.md § 6b](DEPLOYMENT.md#6b-demo--presentation-data).

### Running tests

```bash
./scripts/run_tests.sh            # runs pytest inside the api container
./scripts/run_tests.sh -k letter  # only matching tests
```

## Production deployment

[DEPLOYMENT.md](DEPLOYMENT.md) is the full guide. It covers environment variables, HTTPS with Let's Encrypt, migrations, SMTP, backups and a go-live checklist.

---

## How the scores are calculated

```
raw question scores
  → normalized average per question             (student avg / max points)
  → exam-level DÖÇ score                         DÖÇ_exam   = Σ(w × avg) / Σw
  → course-level DÖÇ score                       DÖÇ_course = mean(midterm, final | make-up)
  → program outcome score                        PÇ         = Σ(w × DÖÇ) / Σw
```

- Course grade = 40% midterm + 60% final. A student who takes the make-up exam gets 60% make-up instead of the final.
- By default, only students who pass the course count toward DÖÇ and PÇ achievement, as in the official template.

See [`api/mudek_service.py`](api/mudek_service.py) for the full logic.

---

*The user interface and some code comments are in Turkish, because the system was built for a Turkish university.*

## License

© 2026 HMZ-VR. All rights reserved.

The source code is published here as a portfolio piece and is free to read. If you would like to reuse or adapt it, please open an issue to get in touch.
