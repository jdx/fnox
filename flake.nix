{
  description = "Fort Knox for your secrets.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      crane,
      nixpkgs,
    }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
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
              [
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
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
                  description = "A flexible secret management tool by @jdx";
                  homepage = "https://github.com/jdx/fnox";
                  changelog = "https://github.com/jdx/fnox/releases/tag/v${cargoToml.version}";
                  license = pkgs.lib.licenses.mit;
                  mainProgram = "fnox";
                  platforms = systems;
                };
              }
            );
        in
        {
          default = fnox;
          fnox = fnox;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/fnox";
        };
      });
    };
}
