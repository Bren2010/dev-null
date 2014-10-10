sjcl = require './sjcl.js'
backdoor = require './ecdh.coffee'

key1 = sjcl.ecc.elGamal.generateKeys sjcl.ecc.curves.c256
key2 = sjcl.ecc.elGamal.generateKeys sjcl.ecc.curves.c256

console.log "Shared secret key: ", sjcl.codec.hex.fromBits key1.sec.dh key2.pub
console.log ''



masterSec = new sjcl.bn limbs: [6603034, 2950496, 9235435, 2502400, 4314946, 9896844, 14125122, 6948731, 10971572, 9274630, 29219]
masterSecKey = new sjcl.ecc.elGamal.secretKey sjcl.ecc.curves.c256, masterSec

x = backdoor.Algorithm3(sjcl.ecc.curves.c256, masterSecKey, key1.pub, key2.pub)

console.log "Leaked private key: ", sjcl.codec.hex.fromBits x
console.log "Derived shared secret key: ", sjcl.codec.hex.fromBits sjcl.hash.sha256.hash key1.pub.C.mult(x).toBits()
