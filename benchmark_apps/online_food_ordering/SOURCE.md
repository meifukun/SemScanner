# Online Food Ordering System

- Packaged application version: 1.0
- Distribution: SourceCodester
- SemScanner target: `http://127.0.0.1:8099/admin/`
- Baseline database: embedded in `semscanner-ae-online-food-ordering:1.0`

The application and its baseline SQLite database are contained in the web
image. This keeps scans from modifying the artifact checkout and makes
container recreation sufficient to remove database changes and uploaded files.
Third-party assets retain the notices distributed with the application.

The packaged image uses PHP 8.1 with SQLite and GD support. This maintained
container runtime is compatible with the PHP 8.0 application used in the
original evaluation and avoids relying on an unversioned, retired base-image
tag.
