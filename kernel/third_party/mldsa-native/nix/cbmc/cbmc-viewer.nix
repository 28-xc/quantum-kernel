# Copyright (c) The mlkem-native project authors
# Copyright (c) The mldsa-native project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

{ stdenvNoCC, python3Packages }:
let
  python = python3Packages.python.withPackages (p: [ p.jinja2 p.voluptuous ]);
in stdenvNoCC.mkDerivation {
  pname = "cbmc-viewer";
  version = "3.12";
  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    install -Dm644 ${../../proofs/cbmc/cbmc-viewer.pyz} $out/lib/cbmc-viewer.pyz
    mkdir -p $out/bin
    cat > $out/bin/cbmc-viewer <<EOF
    #!$SHELL
    exec ${python}/bin/python3 "$out/lib/cbmc-viewer.pyz" "\$@"
    EOF
    chmod +x $out/bin/cbmc-viewer
    ln -s cbmc-viewer $out/bin/cbmc-viewer-xml
  '';
  meta.description = "CBMC Viewer with typed XML result files";
}
