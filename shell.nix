# nix-shell: the library's build inputs, its Ur/Web, and what the tests need.
# `URWEB=/path/to/bin/urweb make check` tests against another compiler,
# e.g. an in-tree build of a modified Ur/Web.
{ pkgs ? import ./nixpkgs.nix }:
let
  urmail = pkgs.callPackage ./derivation.nix { };
in
pkgs.mkShell {
  inputsFrom = [ urmail ];
  packages = with pkgs; [
    curl
    openssl
    python3
  ];
}
