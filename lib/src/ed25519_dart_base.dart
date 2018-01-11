/// Pure Dart implementation of Ed25519 - public-key signature system.
/// For more information, please follow https://ed25519.cr.yp.to.
/// In general, code mimics behaviour of original Python implementation
/// with some extensions from ActiveState Code Recipes
/// (Python 3 Ed25519 recipe - more at https://github.com/ActiveState/code).
/// Code is not tested for security requirements, so it is good idea to use it
/// on trusted local machines!

import 'dart:math' show Random, pow;
import 'dart:typed_data' show Uint8List;

import 'package:pointycastle/pointycastle.dart' show Digest;

// Magic constants
const baseX =
15112221349535400772501151409588531511454012693041857206046113283949847762202;

const baseY =
46316835694926478169428394003475163141307993866256225615783033603165251855960;
const bits = 256;

const d =
37095705934669439343138083508754565189542113879843219016388785533085940283555;
const I =
19681161376707505956807079304988542015446066515923890162744021073123829784752;
const mask =
28948022309329048855892746252171976963317496166410141009864396001978282409976;
const primeL =
7237005577332262213973186563042994240857116359379907606001950938285454250989;
const primeQ =
57896044618658097711785492504343953926634992332820282019728792003956564819949;

List<int> basePoint = const [baseX % primeQ, baseY % primeQ];

/// Clamps the lower and upper bits as required by the specification.
/// Returns [bytes] with clamped bits.
/// Length of the [bytes] should be at least 32.
///
///     var l = new List<int>.generate(32, (int i) => i + i); // [0, ..., 60, 62]
///     bitClamp(new Uint8List.fromList(l)); // [0, ..., 60, 126]
Uint8List bitClamp(Uint8List bytes) {
  bytes[0] &= 248;
  bytes[31] &= 63;
  bytes[31] |= 64;
  return bytes;
}

/// Returns [Uint8List] created from [lst].
/// Shortcut to avoid constructor duplication.
///
///     var bytes = bytesFromList([1, 2, 3]); // [1, 2, 3]
///     print(bytes.runtimeType); // Uint8List
Uint8List bytesFromList(List<int> lst) => new Uint8List.fromList(lst);

/// Converts [bytes] into fixed-size integer.
/// [bytes] length should be at least 32.
///
///     var l = new List<int>.generate(32, (int i) => i + i); // [0, ..., 60, 62]
///     bytesToInteger(l); // 28149809252802682310...81719888435032634998129152
int bytesToInteger(List<int> bytes) {
  num value = 0;
  bytes = bytes.sublist(0, 32);
  for (var i = 0; i < bytes.length; i++) {
    value += bytes[i] * pow(bits, i);
  }
  ;
  return value.toInt();
}

/// Converts integer [intVal] into [x, y] point.
///
///     decodePoint(28149809252802682310); // [2063...9514, 28149809252802682310]
List<int> decodePoint(int intVal) {
  var y = intVal % pow(2, (bits - 1)).toInt();
  var x = xRecover(y);
  if ((x & 1) != ((intVal >> (bits - 1))) & 1) {
    x = primeQ - x;
  }
  ;
  return [x, y];
}

/// Adds points on the Edwards curve.
/// Returns sum of points.
///
///     edwards([1,2], [1,2]); // [38630...2017, 20917...5802]
List<int> edwards(List<int> P, List<int> Q) {
  int x1, y1, x2, y2, x3, y3;
  x1 = P[0];
  y1 = P[1];
  x2 = Q[0];
  y2 = Q[1];
  x3 = (x1 * y2 + x2 * y1) * modularInverse(1 + d * x1 * x2 * y1 * y2);
  y3 = (y1 * y2 + x1 * x2) * modularInverse(1 - d * x1 * x2 * y1 * y2);
  return [x3 % primeQ, y3 % primeQ];
}

/// Encodes point [P] into [Uint8List].
///
///     encodePoint([1,2]); // [2, 0, ..., 0, 0, 128]
Uint8List encodePoint(List<int> P) {
  var x = P[0];
  var y = P[1];
  final encoded = integerToBytes(y + ((x & 1) << 255), 32);
  return encoded;
}

/// Returns digest message of SHA-512 hash function.
/// Digest message is result of hashing message [m].
///
///    Hash(new Uint8List(8)); // [27, 116, ..., 82, 196, 47, 27]
Uint8List Hash(Uint8List m) => new Digest('SHA-512').process(m);

/// Converts integer [e] into [Uint8List] with length [length].
///
///     integerToBytes(1, 32); // [0, 4, ... 0, 0, 0, 0, 0]
Uint8List integerToBytes(int e, int length) {
  var byteList = new Uint8List(length);
  for (var i = 0; i < length; i++) {
    byteList[0 + i] = (e >> (i * 8));
  }
  ;
  return byteList;
}

/// Returns [bool] that that indicates if point [P] is on curve.
///
///     isOnCurve([1, 2]); // false
bool isOnCurve(List<int> P) {
  int x, y;
  x = P[0];
  y = P[1];
  var onCurve = (-x * x + y * y - 1 - d * x * x * y * y) % primeQ == 0;
  return onCurve;
}

/// Returns the modular multiplicative inverse of integer [z]
/// and modulo [primeQ].
///
///     modularInverse(2); // 28948022...41009864396001978282409975
int modularInverse(int z) => z.modInverse(primeQ);

/// Returns integer [x] to the power of `pow(2, p)` with modulo [primeQ].
///
///     modularPow(3, 2); // 81
int modularPow(int x, int p) => x.modPow(pow(2, p).toInt(), primeQ);

/// Generates public key from given secret key [sk].
/// Public key is [Uint8List] with size 32.
///
///     publicKey(new Uint8List.fromList([1,2,3])); // [11, 198,162, ..., 184, 7]
Uint8List publicKey(Uint8List sk) {
  var skHash = Hash(sk);
  var clamped = bytesToInteger(bitClamp(skHash));
  final encoded = encodePoint(scalarMult(basePoint, clamped));
  return encoded;
}

/// Returns result of scalar multiplication of point [P] by integer [e].
///
///     scalarMult([1,2], 10); // [298...422, 480...666]
List<int> scalarMult(List<int> P, int e) {
  if (e == 0) {
    return [0, 1];
  }
  var Q = scalarMult(P, e ~/ 2);
  Q = edwards(Q, Q);
  if (e & 1 > 0) {
    Q = edwards(Q, P);
  }
  ;
  return Q;
}

/// Generates random secret key.
/// Secret key is [Uint8List] with length 64.
///
///     secretKey(); // [224, 185, ..., 10, 17, 137]
Uint8List secretKey() {
  var randGen = new Random.secure();
  var randList = new List<int>.generate(1024, (_) => randGen.nextInt(bits));
  var clamped = bitClamp(Hash(bytesFromList(randList)));
  return clamped;
}


/// Creates signature for message [message] by using secret key [secretKey]
/// and public key [pubKey].
/// Signature is [Uint8List] with size 64.
///
///     var m = new Uint8List(32);
///     var sk = new Uint8List(32);
///     var pk = new Uint8List(32);
///     sign(m, sk, pk); // [62, 244, 231, ..., 53, 213, 0]
Uint8List sign(Uint8List message, Uint8List secretKey, Uint8List pubKey) {
  var secretHash = Hash(secretKey);
  var secretKeyAddMsg = new List<int>.from(secretHash.sublist(32, 64));
  secretKeyAddMsg.addAll(message);
  var msgSecretAsInt = bytesToInteger(Hash(bytesFromList(secretKeyAddMsg)));
  var scalar = encodePoint(scalarMult(basePoint, msgSecretAsInt));
  var preDigest = new List<int>.from(scalar);
  preDigest.addAll(pubKey);
  preDigest.addAll(message);
  var digest = bytesToInteger(Hash(bytesFromList(preDigest)));
  var signature = new List<int>.from(scalar);
  signature.addAll(integerToBytes(
      (msgSecretAsInt + digest * bytesToInteger(bitClamp(secretHash))).toInt() %
          primeL,
      32));
  return bytesFromList(signature);
}

/// Verifies given signature [signature] with message [message] and
/// public key [pubKey].
/// Returns [bool] that indicates if verification is successful.
///
///     var sig = new Uint8List(32);
///     var m = new Uint8List(32);
///     var pk = new Uint8List(32);
///     verifySignature(sig, m, pk); // false
bool verifySignature(Uint8List signature, Uint8List message, Uint8List pubKey) {
  if (signature.lengthInBytes != bits / 4) {
    return false;
  }
  if (pubKey.length != bits / 8) {
    return false;
  }
  var sigSublist = signature.sublist(0, 32);
  var preDigest = new List<int>.from(sigSublist);
  preDigest.addAll(pubKey);
  preDigest.addAll(message);
  var hashInt = bytesToInteger(Hash(bytesFromList(preDigest)));
  var signatureInt = bytesToInteger(signature.sublist(32, 64));
  var signatureScalar = scalarMult(basePoint, signatureInt);
  var pubKeyScalar = scalarMult(decodePoint(bytesToInteger(pubKey)), hashInt);
  var edwardsPubKeyScalar =
  edwards(decodePoint(bytesToInteger(sigSublist)), pubKeyScalar);
  var verified = (signatureScalar.length == edwardsPubKeyScalar.length &&
      signatureScalar[0] == edwardsPubKeyScalar[0] &&
      signatureScalar[1] == edwardsPubKeyScalar[1]);
  return verified;
}

/// Recovers coordinate `x` by given coordinate [y].
/// Returns recovered `x`.
///
///     xRecover(10); // 246881771...00105170855113893569705867530
int xRecover(int y) {
  var xx = (y * y - 1) * modularInverse(d * y * y + 1);

  var x = xx.modPow((primeQ + 3) ~/ 8, primeQ);
  if ((x * x - xx) % primeQ != 0) {
    x = (x * I) % primeQ;
  }

  if (x % 2 != 0) {
    x = primeQ - x;
  }

  return x;
}
