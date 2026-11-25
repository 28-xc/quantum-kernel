// A local interoperability peer. Inputs are deterministic test fixtures.
// Binary data is exchanged only through pipes; no private material is logged.
package main

import (
 "bufio"
 "crypto/mlkem"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "runtime"
)

type request struct { Parameter int; Operation, Seed, Public, Ciphertext string }
type response struct { Public, Ciphertext, Shared, Error, Version string }
func decode(x string) []byte { b,e:=hex.DecodeString(x);if e!=nil {panic(e)};return b }
func run(q request) response {
 r:=response{Version:runtime.Version()}
 if q.Parameter==768 {
  switch q.Operation {
  case "keypair", "decaps":
   k,e:=mlkem.NewDecapsulationKey768(decode(q.Seed));if e!=nil {r.Error=e.Error();break}
   r.Public=hex.EncodeToString(k.EncapsulationKey().Bytes())
   if q.Operation=="decaps" {s,e:=k.Decapsulate(decode(q.Ciphertext));if e!=nil {r.Error=e.Error()} else {r.Shared=hex.EncodeToString(s)}}
  case "encaps":
   k,e:=mlkem.NewEncapsulationKey768(decode(q.Public));if e!=nil {r.Error=e.Error();break}
   s,c:=k.Encapsulate();r.Shared=hex.EncodeToString(s);r.Ciphertext=hex.EncodeToString(c)
  default:r.Error="unknown operation"
  }
 } else if q.Parameter==1024 {
  switch q.Operation {
  case "keypair", "decaps":
   k,e:=mlkem.NewDecapsulationKey1024(decode(q.Seed));if e!=nil {r.Error=e.Error();break}
   r.Public=hex.EncodeToString(k.EncapsulationKey().Bytes())
   if q.Operation=="decaps" {s,e:=k.Decapsulate(decode(q.Ciphertext));if e!=nil {r.Error=e.Error()} else {r.Shared=hex.EncodeToString(s)}}
  case "encaps":
   k,e:=mlkem.NewEncapsulationKey1024(decode(q.Public));if e!=nil {r.Error=e.Error();break}
   s,c:=k.Encapsulate();r.Shared=hex.EncodeToString(s);r.Ciphertext=hex.EncodeToString(c)
  default:r.Error="unknown operation"
  }
 } else {r.Error="unsupported parameter"}
 return r
}
func main() {
 scanner:=bufio.NewScanner(os.Stdin);scanner.Buffer(make([]byte,65536),65536)
 for scanner.Scan() {
  var q request
  if e:=json.Unmarshal(scanner.Bytes(),&q);e!=nil {fmt.Fprintln(os.Stderr,e);os.Exit(2)}
  r:=run(q);b,e:=json.Marshal(r);if e!=nil {panic(e)};fmt.Println(string(b))
 }
 if e:=scanner.Err();e!=nil {fmt.Fprintln(os.Stderr,e);os.Exit(2)}
}
