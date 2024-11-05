{
  description = "py-profinet";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }: let
    overlay = (final: prev: {
      pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [(python-final: python-prev: with python-final; {
        scapy = python-prev.scapy.overrideAttrs (old: {
          patches = (old.patches or []) ++ (lib.optionals stdenv.isDarwin [
            ./scapy/darwin-ioctl.patch
          ]);
        });
      })];
      py-profinet = final.callPackage ./default.nix {};
    });
  in
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ overlay ];
        };
      in {
        packages = rec {
          inherit (pkgs) py-profinet;
          default = py-profinet;
        };
      })) // {
        overlays.default = overlay;
      };
}
