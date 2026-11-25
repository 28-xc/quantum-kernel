# Copyright (c) The mlkem-native project authors
# Copyright (c) The mldsa-native project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

{ stdenvNoCC, python3Packages }:
let
  python = python3Packages.python.withPackages (p: [ p.jinja2 p.voluptuous ]);
in stdenvNoCC.mkDerivation {
  pname = "litani";
  version = "8002c240ef4f424039ed3cc32e076c0234d01768";
  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    install -Dm644 ${../../proofs/cbmc/litani.pyz} $out/lib/litani.pyz
    mkdir -p $out/bin
    cat > $out/bin/litani <<EOF
    #!$SHELL
    exec ${python}/bin/python3 "$out/lib/litani.pyz" "\$@"
    EOF
    chmod +x $out/bin/litani
    ln -s litani $out/bin/litani-xml
  '';
  meta.description = "Litani metabuild system with typed XML result files";
}
