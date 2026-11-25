# Resolve the recorded GitHub revisions and follows edges using their original NAR hashes.
{ self, lock }:
let
  resolve = edge:
    if builtins.isList edge then
      builtins.foldl' (parent: name: resolve lock.nodes.${parent}.inputs.${name}) lock.root edge
    else edge;
  materialize = key: node:
    let
      inputs = builtins.mapAttrs (_: edge: nodes.${resolve edge}) (node.inputs or {});
      pin = node.locked;
      tree = assert pin.type == "github"; builtins.fetchTarball {
        name = "source";
        url = "https://codeload.github.com/${pin.owner}/${pin.repo}/tar.gz/${pin.rev}";
        sha256 = pin.narHash;
      };
      source = builtins.fetchTree {
        type = "path";
        path = tree;
        inherit (pin) rev lastModified narHash;
      };
      outputs = (import (source.outPath + "/flake.nix")).outputs (inputs // { self = result; });
      result = outputs // source // {
        inherit inputs outputs;
        sourceInfo = source;
        _type = "flake";
      };
    in result;
  nodes = builtins.mapAttrs materialize lock.nodes;
  rootInputs = builtins.mapAttrs (_: edge: nodes.${resolve edge}) lock.nodes.${lock.root}.inputs;
in
assert lock.version == 7;
rootInputs // { inherit self; }
