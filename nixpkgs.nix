# The nixpkgs the standalone build and shell use: one release of the
# nixos-unstable channel, pinned by its path on releases.nixos.org, which
# does not move (the channel's own URL does, and a fixed hash on it breaks
# as soon as the channel advances).  To move on: pick the release that
# https://channels.nixos.org/nixos-unstable/git-revision redirects to and
# run `nix-prefetch-url --unpack` on its nixexprs.tar.xz.
import (builtins.fetchTarball {
  # nixos-unstable at e94cb152ed51bd6e24eb4a41f1460252beb52cd2 (2026-09)
  url = "https://releases.nixos.org/nixos/unstable/nixos-26.11pre1079315.e94cb152ed51/nixexprs.tar.xz";
  sha256 = "0g733fdjwfjhn6rq3m4fjj32fpqkkrivb877k14axk85kyiwd04v";
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
