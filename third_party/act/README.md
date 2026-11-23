# act (pinned) and the CI runner image

`.github/workflows/ci.yml` is checked locally with
[nektos/act](https://github.com/nektos/act) before it's pushed. act runs each
job in a container that has only what a fresh GitHub runner has, so it also
catches a build or test that quietly depends on something of the developer's
machine.

## Pins

Neither is a host install.

- **act** v0.2.89, the Linux x86-64 release tarball, an `http_archive` in
  `MODULE.bazel` (`@act`), sha256
  `0191d6f1f3b716b5c55820032605d05fc3c1cdbf581ebeff655019e5dd1524c0`.
- **Runner image** `runner_image.txt`: `ghcr.io/catthehacker/ubuntu` by
  digest (Ubuntu 24.04 with the tools of GitHub's `ubuntu-24.04` image that
  actions commonly need). act maps `runs-on: ubuntu-latest` and
  `ubuntu-24.04` to it.

## Running a job

```
bazel run //third_party/act -- -j test
bazel run //third_party/act -- -j release --eventpath .github/ci/act-dispatch.json
bazel run //third_party/act -- --list
```

Everything after `--` goes to act. It needs a container engine: Docker, from
a shell in the `docker` group or a rootless Docker named by `DOCKER_HOST`, or
rootless Podman with `WL_ACT_PODMAN=1` (which points act at
`$XDG_RUNTIME_DIR/podman/podman.sock`). `WL_ACT_DOCKER_UNIT=<user unit>` runs
the engine only for the duration: the wrapper starts that systemd user unit
first and stops it when act exits. For example, with a rootless dockerd as
the user unit `docker-rootless.service`:

```
WL_ACT_DOCKER_UNIT=docker-rootless.service \
DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock \
  bazel run //third_party/act -- -j test
```

The wrapper (`act.sh.tpl`) adds the pinned image for both `runs-on` labels, a container
label `wait-listen.owner=act` and a memory cap (`WL_ACT_MEMORY`, default 6g),
`--rm`, and keeps act's action cache, cache server and artifacts in `.act/`
of the checkout (gitignored; `WL_ACT_STATE` overrides).

Under act, the release job builds and checks the binaries but doesn't
publish them: its publish step is skipped when `ACT` is set.
