import 'dart:typed_data' show Uint8List;

import 'package:ed25519_dart/ed25519_dart.dart';
import 'package:test/test.dart';

void main() {
  test("bitClamp() clamps bits in provided lists as expected", () {
    var testData = new Uint8List(32);
    var testData2 = new Uint8List.fromList(
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
    var expected = new Uint8List.fromList(
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 64
        ]);
    var expected2 = new Uint8List.fromList(
        [0, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64
        ]
    );
    expect(bitClamp(testData), equals(expected));
    expect(bitClamp(testData2), equals(expected2));
  });

  test("bytesFromList() converts List into Uint8List", () {
    var testData = new List<int>.filled(32, 0);
    var expected = new Uint8List(32);
    expect(bytesFromList(testData), equals(expected));
    expect((bytesFromList(testData) is Uint8List), equals(true));
  });
  test("bytesToInteger() converts List of integers into integer", () {
    var testData = new List<int>.filled(32, 0);
    var testData2 = new List<int>.filled(32, 2);
    var expected = 0;
    var expected2 = 908173248920127022929968509872062022378588115024631874819275168689514742274;
    expect(bytesToInteger(testData), equals(expected));
    expect(bytesToInteger(testData2), equals(expected2));
  });
  test("decodePoint() creates expected point x-y point from passed integer", () {
    var testData = 1024128256;
    var expected = [5049901154188754798176685959377395864974690556190068451341045359400187598236, 1024128256];
    expect(decodePoint(testData), equals(expected));
  });
  test("edwards() adds two x-y points with expected result", () {
    var testData = [1,2];
    var expected = [38630462183868106874449484850498687242488459434265729964110945788313160992017,
                    2091706204615399755245742503625476174616215419841867942895091432328977195802];
    expect(edwards(testData, testData), equals(expected));
  });
  test("encodePoint() creates expected Uint8List from x-y point", () {
    var testData = [1,2];
    var expected = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128];
    expect(encodePoint(testData), equals(expected));
  });
  test("Hash() hashes passed Uint8List into expected digest", () {
    var testData = new Uint8List(2);
    var expected = [94, 167, 29, 198, 208, 180, 245, 123, 243, 154, 173, 208,
                   124, 32, 140, 53, 240, 108, 210, 186, 197, 253, 226, 16, 57,
                   127, 112, 222, 17, 212, 57, 198, 46, 193, 205, 243, 24, 55,
                   88, 134, 95, 211, 135, 252, 234, 11, 173, 162, 246, 195, 122,
                   74, 23, 133, 29, 209, 215, 143, 239, 230, 242, 4, 238, 84];
    expect(Hash(testData), equals(expected));
  });
  test("integerToBytes() converts passed integer into expected Uint8List", () {
    var testData = 1024;
    var expected = [0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    expect(integerToBytes(testData, 32), equals(expected));
    expect(integerToBytes(testData, 32).length, equals(32));
  });
  test("isOnCurve() checks if passed point is on curve", () {
    var testData = [15112221349535400772501151409588531511454012693041857206046113283949847762202,
                   46316835694926478169428394003475163141307993866256225615783033603165251855960];
    var testData2 = [1, 2];
    expect(isOnCurve(testData), equals(true));
    expect(isOnCurve(testData2), equals(false));
  });
  test("modularInverse() returns expected modular inverse", () {
    var testData = 2;
    var expected = 28948022309329048855892746252171976963317496166410141009864396001978282409975;
    expect(modularInverse(testData), equals(expected));
  });
  test("modularPow() computes and returns expected integer", () {
    var testData = 2;
    var expected = 256;
    expect(modularPow(testData, testData + 1), equals(expected));
  });

  test("publicKey() creates expected public key from passed secret key", () {
    var testData = new Uint8List(32);
    var expected = [59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42,
                   111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192,
                   72, 161, 139, 89, 218, 41];
    expect(publicKey(testData), equals(expected));
  });
  test("scalarMult() returns expected scalar multiplication of point", () {
    var testData = [1, 2];
    var expected = [2985072665741473095974513523900639186165599576139095168757154406154247914422,
                   48018218743393111964698292971632252982314570786198777847490644689840463716666];
    expect(scalarMult(testData, 10), equals(expected));
  });
  test("secretKey() returns random Uint8List with length 64", () {
    expect(secretKey().length, equals(64));
    expect((secretKey() is Uint8List), equals(true));
    expect(secretKey(1024).length, equals(64));
    expect((secretKey(1024) is Uint8List), equals(true));
  });
  test("sign() creates expected signature from passed parameters", () {
    var testData = new Uint8List(32);
    var expected = [62, 244, 112, 248, 0, 94, 55, 252, 113, 25, 122, 42, 208,
                   19, 144, 190, 229, 49, 127, 202, 143, 134, 163, 254, 26,
                   249, 204, 56, 245, 59, 169, 119, 177, 186, 224, 82, 94, 135,
                   255, 168, 240, 69, 169, 176, 231, 173, 200, 218, 4, 199, 186,
                   189, 225, 87, 155, 188, 192, 200, 82, 57, 113, 53, 213, 0];

    expect(sign(testData, testData, testData), equals(expected));
  });
  test("verifySignature() verifies signature by passed parameters", () {
    var testMessage = new Uint8List(32);
    var testPubKey = new Uint8List.fromList([57, 155, 96, 34, 234, 193, 54, 237, 157, 35, 24, 27, 183,
    158, 136, 254, 210, 211, 23, 93, 11, 51, 194, 141, 243, 85, 24, 152, 235,
    37, 55, 208]);
    var testSignature = new Uint8List.fromList([93, 80, 8, 206, 62, 55, 22, 162, 0, 162, 148, 32, 147,
                        9, 11, 227, 29, 64, 124, 140, 120, 58, 82, 207, 38, 112,
                        49, 145, 56, 131, 234, 108, 86, 147, 148, 31, 222, 23,
                        188, 196, 227, 234, 41, 234, 218, 8, 30, 93, 136, 117,
                        196, 32, 223, 180, 71, 106, 220, 89, 99, 116, 190, 214,
                        207, 0]);
    expect(verifySignature(testSignature, testMessage, testPubKey), equals(true));
  });
  test("xRecover() computes expected value from passed integer", () {
    var testData = 5;
    var expected = 39662079413846548812394406357884595898465868971068617279194812783497449546402;
    expect(xRecover(testData), equals(expected));
  });
}