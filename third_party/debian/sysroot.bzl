"""Sysroots made of pinned Debian packages (third_party/debian/lock.json).

toolchains_llvm needs a sysroot that is files in a repository, so each
architecture's packages are downloaded (by URL, checked against the lock's
SHA-256) and unpacked into one repository per sysroot, @debian_sysroot_<name>
(lock.json "sysroots").
"""

def _merge(rctx, src, dst):
    """Symlinks every file under src to the same relative path under dst."""
    todo = [""]
    for _ in range(10000):  # Starlark has no while; bounded walk
        if not todo:
            return
        rel = todo.pop()
        for entry in rctx.path(src + rel).readdir():
            sub = rel + "/" + entry.basename
            if entry.is_dir:
                todo.append(sub)
                continue
            target = rctx.path(dst + sub)
            if target.exists:
                fail("%s%s collides with %s%s" % (src, sub, dst, sub))

            # rctx.symlink resolves a relative target from the repository's
            # root (not the link's directory).
            rctx.symlink(src + sub, dst + sub)
    fail("%s: directory walk didn't finish" % src)

def _sysroot_impl(rctx):
    lock = json.decode(rctx.read(rctx.attr.lock))
    pkgs = lock["sysroots"][rctx.attr.sysroot]["packages"]
    for name in sorted(pkgs):
        p = pkgs[name]

        # A .deb is an ar archive; Bazel's "deb" type only splits it into its
        # members, so unpack the data member in a second step.
        tmp = "_debs/" + name
        rctx.download_and_extract(
            url = p["url"],
            sha256 = p["sha256"],
            type = "deb",
            output = tmp,
        )
        data = [f for f in rctx.path(tmp).readdir() if f.basename.startswith("data.tar")]
        if len(data) != 1:
            fail("%s: expected one data.tar member, found %s" % (name, data))
        rctx.extract(data[0], output = ".")
    rctx.delete("_debs")

    # Debian keeps musl in multiarch directories Clang doesn't search for a
    # *-linux-musl target. Link its files into the plain layout of a musl
    # system (merging with the kernel headers already in usr/include), and
    # the architecture's UAPI asm/ to usr/include/asm. (glibc sysroots are
    # already laid out as Clang expects.)
    if rctx.attr.musl_multiarch:
        _merge(rctx, "usr/include/" + rctx.attr.musl_multiarch, "usr/include")
        _merge(rctx, "usr/lib/" + rctx.attr.musl_multiarch, "usr/lib")
        rctx.symlink("usr/include/" + rctx.attr.gnu_multiarch + "/asm", "usr/include/asm")
    rctx.file("BUILD.bazel", """\
filegroup(
    name = "sysroot",
    # bookworm-era packages still install libc into /lib (not merged /usr).
    srcs = glob(["usr/**"], allow_empty = False) + glob(["lib/**", "lib64/**"], allow_empty = True),
    visibility = ["//visibility:public"],
)

exports_files(glob(["usr/lib/llvm-*/lib/clang/*/lib/linux/*"], allow_empty = True))

# For the test VMs: a kernel image, the dynamic loader, and the binaries, by
# role rather than by (versioned) file name.
filegroup(
    name = "kernel",
    srcs = glob(["boot/vmlinuz-*"], allow_empty = True),
    visibility = ["//visibility:public"],
)

filegroup(
    name = "dynamic_loader",
    srcs = glob(["usr/lib/*/ld-linux*.so.*"], allow_empty = True),
    visibility = ["//visibility:public"],
)

exports_files(glob(["usr/bin/*"], allow_empty = True))

# The kernel's UAPI headers alone (linux/, asm-generic/, each architecture's
# asm/), for code that must not see the libc, such as BPF programs.
filegroup(
    name = "kernel_headers",
    srcs = glob(
        ["usr/include/linux/**", "usr/include/asm-generic/**", "usr/include/*-linux-gnu*/asm/**"],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)
""")

debian_sysroot = repository_rule(
    implementation = _sysroot_impl,
    attrs = {
        "gnu_multiarch": attr.string(),
        "lock": attr.label(mandatory = True, allow_single_file = True),
        "musl_multiarch": attr.string(),
        "sysroot": attr.string(mandatory = True),
    },
)

def _ext_impl(mctx):
    lock_label = Label("//third_party/debian:lock.json")
    lock = json.decode(mctx.read(mctx.path(lock_label)))
    for name, entry in lock["sysroots"].items():
        debian_sysroot(
            name = "debian_sysroot_" + name,
            gnu_multiarch = entry.get("gnu_multiarch", ""),
            lock = lock_label,
            musl_multiarch = entry.get("musl_multiarch", ""),
            sysroot = name,
        )
    return mctx.extension_metadata(reproducible = True)

debian_sysroots = module_extension(implementation = _ext_impl)
