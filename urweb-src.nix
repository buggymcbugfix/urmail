# The Ur/Web the standalone build and shell use. A project that packages
# this library passes its own `urweb` to derivation.nix instead.
#
# The library needs the io monad (Basis.io, runTransaction), which is in
# buggymcbugfix/urweb's main from the commit "io: computations outside any
# transaction, and periodic tasks in them" on, and Basis.checkServedFile,
# from "Basis: blessServedFile and checkServedFile, the files of `file`
# directives" on. The commit below is the one warenwirtschaft's flake
# pins. It is fetched as GitHub's tarball of it, with the hash of the
# unpacked tree, which `git archive` of the commit reproduces, so the fetch
# is checked and can be cached.
builtins.fetchTarball {
  # buggymcbugfix/urweb main at fd6793759f07 (2026-09-29)
  url = "https://github.com/buggymcbugfix/urweb/archive/fd6793759f075d50123dfeb9421fbf188d23710c.tar.gz";
  sha256 = "0zn5s16fa9sd9d0d7ndkiqcv7jrd0wywnbs3cphg8h6vkpkh46wh";
}
