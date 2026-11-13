{
  description = "veil-tell development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }: {
    devShells = nixpkgs.lib.genAttrs [
      "aarch64-darwin" "aarch64-linux" "x86_64-linux"
    ] (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in {
        default = pkgs.mkShell {
          packages = with pkgs; [ rustup mise python3 openssl ]
            ++ lib.optionals stdenv.isLinux [ bubblewrap iproute2 util-linux ];
          shellHook = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
            export VEIL_TELL_BWRAP="${pkgs.bubblewrap}/bin/bwrap"
          '';
        };
      });
  };
}
