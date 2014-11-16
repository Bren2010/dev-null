sjcl = require './sjcl.js'
backdoor = require './ecdh.coffee'

key1 = sjcl.ecc.elGamal.generateKeys sjcl.ecc.curves.c256
key2 = sjcl.ecc.elGamal.generateKeys sjcl.ecc.curves.c256

console.log "First public key: ", sjcl.codec.hex.fromBits key1.pub.C.toBits()
console.log "Second public key: ", sjcl.codec.hex.fromBits key2.pub.C.toBits()
console.log ''

console.log "Shared secret key: ", sjcl.codec.hex.fromBits key1.sec.dh key2.pub
console.log ''



masterSec = new sjcl.bn("0x72238d8506a769b46a077bd7884297038c41d742262f008cebeb2d056064c11a")
masterSecKey = new sjcl.ecc.elGamal.secretKey sjcl.ecc.curves.c256, masterSec

x = backdoor.Algorithm3(sjcl.ecc.curves.c256, masterSecKey, key1.pub, key2.pub)

console.log "Leaked private key: ", sjcl.codec.hex.fromBits x
console.log "Derived shared secret key: ", sjcl.codec.hex.fromBits sjcl.hash.sha256.hash key1.pub.C.mult(x).toBits()
