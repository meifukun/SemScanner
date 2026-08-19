# changedetection.io 0.45.20

- Packaged application: changedetection.io 0.45.20 (LinuxServer.io image
  `0.45.20-ls101`, released 2024-04-24)
- Upstream project: <https://github.com/dgtlmoon/changedetection.io>
- Container image source: `linuxserver/changedetection.io:0.45.20`
- Upstream image content digest: `sha256:862573ec3f64e5fbb9ef89421b0a1c5e2564b175bbfcea775bc4b74540c75ced`
- SemScanner target: `http://127.0.0.1:4328/login`
- Fixed password: `admin123` (password-only login; no username is required)
- Baseline: one paused local watch at `http://web:5000/`, with no history
  snapshots. The baseline is copied into a fresh `/config` volume by the
  entrypoint and is restored by `./manage.sh reset changedetection`.

The prebuilt image archive contains the complete application runtime and its
Python source, so artifact evaluation does not require downloading the
application source or image. The application and its dependencies retain their
upstream licenses; see the upstream repository for the license text.
