{ pkgs ? import ./nixpkgs.nix }:
pkgs.callPackage ./derivation.nix { }
