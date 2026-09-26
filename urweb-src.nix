# The Ur/Web the standalone build and shell use. A project that packages
# this library passes its own `urweb` to derivation.nix instead.
builtins.fetchGit {
  url = "https://github.com/buggymcbugfix/urweb";
  ref = "main";
  rev = "39836a619553c730414bca2c2045618b46e90df7";
}
