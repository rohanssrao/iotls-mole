{
  description = "IoTLS-Mole dev/test shell for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            uv
            python3
            libpcap
            iproute2
            iptables
            tcpdump
            openssl
          ];

          shellHook = ''
            export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [ pkgs.libpcap ]}:$LD_LIBRARY_PATH
            echo "IoTLS-Mole Nix shell: LD_LIBRARY_PATH includes libpcap"
            echo "Run with: sudo -E env PATH=\"\$PATH\" LD_LIBRARY_PATH=\"\$LD_LIBRARY_PATH\" uv run iotls-mole <target-ip>"
          '';
        };
      });
    };
}
