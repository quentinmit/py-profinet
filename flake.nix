{
  description = "py-profinet";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.simpleFlake {
      inherit self nixpkgs;
      name = "py-profinet";
      overlay = (final: prev: {
        pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [(python-final: python-prev: with python-final; {
          scapy = python-prev.scapy.overrideAttrs (old: {
            patches = (old.patches or []) ++ (lib.optionals stdenv.isDarwin [
              ./scapy/darwin-ioctl.patch
            ]);
          });
        })];
        py-profinet = {
          py-profinet = final.callPackage ./default.nix {};
        };
      });
      #shell = ./shell.nix;
    };
}
