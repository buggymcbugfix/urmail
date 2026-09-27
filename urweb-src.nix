# The Ur/Web the standalone build and shell use. A project that packages
# this library passes its own `urweb` to derivation.nix instead.
#
# The library needs the io monad (Basis.io, runTransaction), which is in
# buggymcbugfix/urweb's main from the commit "io: computations outside any
# transaction, and periodic tasks in them" on, and Basis.checkServedFile,
# from "Basis: blessServedFile and checkServedFile, the files of `file`
# directives" on; move the rev forward once they are there.
builtins.fetchGit {
  url = "https://github.com/buggymcbugfix/urweb";
  ref = "main";
  rev = "39836a619553c730414bca2c2045618b46e90df7";
}
