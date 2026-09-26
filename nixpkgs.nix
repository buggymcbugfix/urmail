import (builtins.fetchTarball {
  url = https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz;
  # Hash obtained using `nix-prefetch-url --unpack <url>`
  sha256 = "sha256:8S3Kcxs7D4UtxJxSJZz0m14CGhuW0MxfrIwJxeGWGnQ=";
}) {
  overlays = [
    (final: prev: {
      mlton20210117 = prev.mlton20210117.override {
        doCheck = !prev.stdenv.hostPlatform.isDarwin;
      };
      urweb = final.callPackage "${import ./urweb-src.nix}/derivation.nix" { };
    })
  ];
}
