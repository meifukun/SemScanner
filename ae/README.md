# SemScanner AE Runtime

This directory defines the containerized SemScanner runtime used for artifact
evaluation. The image contains the current SemScanner source, Python 3.11,
Chromium, a version-matched ChromeDriver, `sqlmap`, `curl`, and the Python
dependencies required by the scanner. The vulnerable target applications
remain in independent Compose projects under `benchmark_apps/`.

The supported interface is the top-level wrapper. On a `linux/amd64` host with
Docker Engine and Docker Compose v2, load the packaged runtime and check it
without making an LLM request:

```bash
./ae.sh load
./ae.sh doctor
./ae.sh doctor loan
```

`doctor loan` resets Loan Management System, attaches the runtime container to
the target's Docker network, and verifies that headless Chromium can reach it.
It does not call the LLM API. The same command accepts `online-food`,
`e-learning`, and `changedetection`.

To run a scan against one of the packaged, intentionally vulnerable targets:

```bash
export LLM_API_KEY="<API-KEY>"
export LLM_BASE_URL="<OPENAI-COMPATIBLE-ENDPOINT>"
export LLM_MODEL="<MODEL-NAME>"
./ae.sh run loan
```

`run` restores the selected target to its packaged baseline before scanning
and writes results under `ae_results/<TARGET>/<RUN-ID>/`. Attack tasks execute
one at a time by default for reproducibility. Use these commands only with the
packaged targets or another system that you are authorized to test.

If the runtime archive is not present, build the image from the included source:

```bash
./ae.sh build
```

For rapid development, `./ae.sh run-dev TARGET` mounts the current source tree
read-only over the source baked into the image. Rebuild with `./ae.sh build`
before testing the release path.

Create the offline runtime archive with:

```bash
./ae.sh export
```

The archive is written to `ae/images/`. The application images have a separate
offline archive under `benchmark_apps/images/`. Both archives are excluded
from ordinary Git history and included in the complete artifact attached to
the GitHub Release.
