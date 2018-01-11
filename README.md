# ed25519_dart

Pure Dart implementation of Ed25519 - public-key signature system.
For more information, please follow [here](https://ed25519.cr.yp.to).

In general, code mimics behaviour of original Python implementation
with some extensions from [ActiveState Code Recipes](https://github.com/ActiveState/code).
Code is not tested for security requirements, so it is good idea to use it
on trusted local machines!

## Usage

A simple usage example:
```dart   
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
```

## Package documentation
Extended package documentation can be found [here](https://www.dartdocs.org/documentation/ed25519_dart/0.0.1/).
