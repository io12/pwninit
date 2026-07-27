{
  description = "pwninit - automate starting binary exploit challenges";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib;
        manifest = lib.importTOML ./Cargo.toml;

        mk =
          pkgs:
          pkgs.rustPlatform.buildRustPackage {
            pname = manifest.package.name;
            version = manifest.package.version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs = with pkgs; [
              xz
              openssl
            ];
          };
      in
      {
        packages = {
          default = mk pkgs;
          static = mk pkgs.pkgsStatic;
        };
      }
    );
}
