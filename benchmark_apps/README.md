# Packaged Benchmark Applications

This directory contains four intentionally vulnerable web applications used
for the SemScanner artifact evaluation. Each application is packaged as an
independent Docker Compose project with a fixed baseline database. The services
bind only to `127.0.0.1` by default.

> **Security warning:** Run these applications only on a local test machine or
> another isolated, authorized environment. Do not expose their ports to an
> untrusted network.

## Prerequisites

- Docker Engine with the Compose v2 plugin
- A user account that can run Docker commands
- `curl`

No host-side PHP, Apache, MySQL, or SQLite installation is required.

The complete artifact attached to the GitHub Release contains
`images/semscanner-ae-targets-amd64.tar.gz`. The management script loads its
packaged Web and database images automatically. A source-only Git checkout does
not contain these images and cannot deploy the targets until the Release
artifact has been downloaded.

## Quick start

From this directory, reset and start one application:

```bash
./manage.sh reset loan
./manage.sh reset online-food
./manage.sh reset e-learning
./manage.sh reset changedetection
```

All four can also be prepared with one command:

```bash
./manage.sh reset all
```

The reset operation removes only the selected Compose project's containers and
state volumes. It then recreates the application from its packaged images,
waits for the HTTP endpoint, and verifies the baseline data.

## Targets and credentials

| Target | URL | SemScanner login instruction |
| --- | --- | --- |
| Loan Management System | `http://127.0.0.1:8082/login.php` | `Log in as administrator with username admin and password admin123.` |
| Online Food Ordering System | `http://127.0.0.1:8099/admin/` | `Log in to the admin panel with username admin and password admin123.` |
| Simple E-Learning System | `http://127.0.0.1:8081/` | `Log in with email cblake@mail.com and password cblake123.` |
| changedetection.io 0.45.20 | `http://127.0.0.1:4328/login` | `Log in with password admin123. This application does not require a username.` |

The corresponding crawl start URLs are `http://127.0.0.1:8082/`,
`http://127.0.0.1:8099/admin/`, `http://127.0.0.1:8081/`, and
`http://127.0.0.1:4328/`.

## Management commands

```bash
./manage.sh start TARGET
./manage.sh reset TARGET
./manage.sh health TARGET
./manage.sh verify-reset TARGET
./manage.sh status TARGET
./manage.sh logs TARGET
./manage.sh stop TARGET
```

`TARGET` may be `loan`, `online-food`, `e-learning`, `changedetection`, or
`all` where applicable.
`start` preserves the current database state, whereas `reset` restores the
packaged baseline. Run `reset` before every independent SemScanner experiment.

If a default port is already occupied, override it when running the command:

```bash
LOAN_PORT=18082 FOOD_PORT=18099 ELEARNING_PORT=18081 CHANGEDETECTION_PORT=14328 \
  ./manage.sh reset all
```

Use the same port values in the corresponding SemScanner target URLs.

## Directory layout

Each target directory contains:

- `compose.yaml`: the web and database services required by that target;
- `SOURCE.md`: upstream provenance and local packaging notes.

The application code and initial database contents are encapsulated in the
prebuilt target images rather than duplicated in this repository.

Application runtime changes remain inside containers or named database volumes.
Consequently, `./manage.sh reset TARGET` also removes uploaded test files and
other state produced by a previous scan.

## Preparing the Release image bundle

Maintainers can export the six loaded application and database images into the
Release archive with:

```bash
./export_images.sh
```

The resulting archive is written under `images/`. Large image archives are
intentionally excluded from ordinary Git history and included in the complete
artifact attached to the GitHub Release.
