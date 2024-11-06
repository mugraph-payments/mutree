{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        inherit (pkgs)
          makeRustPlatform
          mkShell
          rust-bin
          ;

        rust = rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustPlatform = makeRustPlatform {
          rustc = rust;
          cargo = rust;
        };

        packages.default = rustPlatform.buildRustPackage {
          name = "mucrdt";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
        };
      in
      {
        inherit packages;

        devShells.default = mkShell {
          name = "mucrdt";

          buildInputs = with pkgs; [
            rust

            cargo-machete
            cargo-mutants
            cargo-nextest
            cargo-pgo
            cargo-tarpaulin
            cargo-watch
            llvmPackages_19.bolt
          ];
        };
      }
    );
}
