{
  description = "Fort Knox for your secrets.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      crane,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;
        src = pkgs.lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter =
            path: type:
            (craneLib.filterCargoSources path type) || (pkgs.lib.hasInfix "/src/assets/" (toString path));
        };
        commonArgs = {
          inherit src;
          strictDeps = true;
          nativeBuildInputs = with pkgs; [
            perl
            pkg-config
          ];
          buildInputs =
            with pkgs;
            [ ]
            ++ lib.optionals stdenv.isLinux [
              dbus
              udev
            ];
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        fnox =
          let
            cargoToml = craneLib.crateNameFromCargoToml { inherit src; };
          in
          craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
              meta = {
                mainProgram = "fnox";
                description = "A flexible secret management tool by @jdx";
                homepage = "https://github.com/jdx/fnox";
                changelog = "https://github.com/jdx/fnox/releases/tag/v${cargoToml.version}";
                license = pkgs.lib.licenses.mit;
                platforms = flake-utils.lib.defaultSystems;
              };
            }
          );
      in
      {
        packages = {
          default = fnox;
          fnox = fnox;
        };

        apps.default = {
          type = "app";
          program = "${fnox}/bin/fnox";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            clippy
            rustfmt
          ];
        };
      }
    );
}
