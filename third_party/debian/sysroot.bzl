"""Sysroots made of pinned Debian packages (third_party/debian/lock.json).

toolchains_llvm needs a sysroot that is files in a repository, so each
architecture's packages are downloaded (by URL, checked against the lock's
SHA-256) and unpacked into one repository, @debian_sysroot_<arch>.
"""

def _sysroot_impl(rctx):
    lock = json.decode(rctx.read(rctx.attr.lock))
    pkgs = lock["packages"][rctx.attr.arch]
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
    rctx.file("BUILD.bazel", """\
filegroup(
    name = "sysroot",
    srcs = glob(["usr/**"], allow_empty = False),
    visibility = ["//visibility:public"],
)
""")

debian_sysroot = repository_rule(
    implementation = _sysroot_impl,
    attrs = {
        "arch": attr.string(mandatory = True),
        "lock": attr.label(mandatory = True, allow_single_file = True),
    },
)

def _ext_impl(mctx):
    for arch in ["amd64", "armhf"]:
        debian_sysroot(
            name = "debian_sysroot_" + arch,
            arch = arch,
            lock = "//third_party/debian:lock.json",
        )
    return mctx.extension_metadata(reproducible = True)

debian_sysroots = module_extension(implementation = _ext_impl)
