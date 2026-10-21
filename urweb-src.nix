# The Ur/Web the standalone build and shell use. A project that packages
# this library passes its own `urweb` to derivation.nix instead.
#
# The library needs the io monad (Basis.io, runTransaction), which Ur/Web
# has from the commit "io: computations outside any transaction, and
# periodic tasks in them" on, and Basis.checkServedFile, from "Basis:
# blessServedFile and checkServedFile, the files of `file` directives" on.
# The commit below is buggymcbugfix/urweb-research's main, which
# warenwirtschaft builds against. That repository is private, so it is
# fetched over ssh with the key of whoever builds, as warenwirtschaft's
# flake fetches it. The rev pins it: the commit's hash fixes the tree, so
# no other hash is needed.
builtins.fetchGit {
  # buggymcbugfix/urweb-research main at 961a7ae15d31 (2026-10-21)
  url = "ssh://git@github.com/buggymcbugfix/urweb-research.git";
  rev = "961a7ae15d313e192eecaefc6008791ab5c1c25a";
}
