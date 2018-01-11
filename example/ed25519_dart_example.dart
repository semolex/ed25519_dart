import 'package:ed25519_dart/ed25519_dart.dart';

void main() {
  // Create new random secret key
  var sk = secretKey();
  print("Created random secret key with length - ${sk.length}");
// Derive public key from secret key
  var pk = publicKey(sk);
  print("Derived public key with length ${pk.length} from secret key");
// Create simple message from list
  var msg = bytesFromList([1, 2, 3, 4]);
  print("Created simple message - $msg");
// Sign message with pk secret ley and public key
  var signature = sign(msg, sk, pk);
  print("Message signed by secret and public key");
// Verify message signature with public key
  var isVerified = verifySignature(signature, msg, pk);
  print("Created signature is verified - $isVerified");
}
