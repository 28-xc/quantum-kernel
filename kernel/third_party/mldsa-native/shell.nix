{ name ? "default", system ? builtins.currentSystem }:
let
  project = builtins.getFlake ("path:" + toString ./.);
in project.devShells.${system}.${name}
