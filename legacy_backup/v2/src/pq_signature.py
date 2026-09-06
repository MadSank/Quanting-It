from typing import Tuple, Any
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization

class ML_DSA_SIGNER:
    """
    [REAL POST-QUANTUM SIGNATURE LAYER]
    
    This implementation uses NIST FIPS 204 ML-DSA-65 from the cryptography library.
    It provides classical post-quantum security to authenticate the message.
    """
    
    @staticmethod
    def generate_keys() -> Tuple[str, Any]:
        """
        Generates a real ML-DSA-65 keypair.
        Returns (public_key_hex, private_key_object).
        """
        private_key = mldsa.MLDSA65PrivateKey.generate()
        public_key = private_key.public_key()
        
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return pub_bytes.hex(), private_key
        
    @staticmethod
    def sign(message_digest: str, private_key_obj: Any, public_key_hex: str = None) -> str:
        """
        Signs the message digest using ML-DSA-65.
        Returns the signature as a hex string.
        """
        signature = private_key_obj.sign(message_digest.encode('utf-8'))
        return signature.hex()

    @staticmethod
    def verify(message_digest: str, signature_hex: str, public_key_hex: str, **kwargs) -> bool:
        """
        Verifies the ML-DSA-65 signature.
        """
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            public_key = mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
            
            signature_bytes = bytes.fromhex(signature_hex)
            
            public_key.verify(signature_bytes, message_digest.encode('utf-8'))
            return True
        except Exception:
            return False

# Expose the ML_DSA_SIGNER as DEMO_PQ_SIGNER
DEMO_PQ_SIGNER = ML_DSA_SIGNER
