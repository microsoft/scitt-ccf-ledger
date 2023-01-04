# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import datetime
import hashlib
import json
import warnings
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
from uuid import uuid4

warnings.filterwarnings("ignore", category=Warning)

import cbor2
import jwt
import pycose.algorithms
import pycose.headers
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_private_key,
    load_ssh_public_key,
)
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from pycose.keys.curves import P256, P384, P521, Ed25519
from pycose.keys.ec2 import EC2Key
from pycose.keys.keyparam import (
    EC2KpCurve,
    EC2KpD,
    EC2KpX,
    EC2KpY,
    OKPKpCurve,
    OKPKpD,
    OKPKpX,
    RSAKpD,
    RSAKpDP,
    RSAKpDQ,
    RSAKpE,
    RSAKpN,
    RSAKpP,
    RSAKpQ,
    RSAKpQInv,
)
from pycose.keys.okp import OKPKey
from pycose.keys.rsa import RSAKey
from pycose.messages import CoseMessage, Sign1Message

from .receipt import Receipt

RECOMMENDED_RSA_PUBLIC_EXPONENT = 65537

REGISTERED_EC_CURVES = {
    "P-256": P256,
    "P-384": P384,
    "P-521": P521,
}

Pem = str

COSE_HEADER_PARAM_ISSUER = 391
COSE_HEADER_PARAM_FEED = 392
COSE_HEADER_PARAM_REGISTRATION_INFO = 393
COSE_HEADER_PARAM_SCITT_RECEIPTS = 394

RegistrationInfoValue = Union[str, bytes, int]
RegistrationInfo = Dict[str, RegistrationInfoValue]


def generate_rsa_keypair(key_size: int) -> Tuple[Pem, Pem]:
    priv = rsa.generate_private_key(
        public_exponent=RECOMMENDED_RSA_PUBLIC_EXPONENT,
        key_size=key_size,
        backend=default_backend(),
    )
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return priv_pem, pub_pem


def generate_ec_keypair(curve: str) -> Tuple[Pem, Pem]:
    if curve not in REGISTERED_EC_CURVES:
        raise NotImplementedError(f"Unsupported curve: {curve}")
    priv = ec.generate_private_key(
        curve=REGISTERED_EC_CURVES[curve].curve_obj, backend=default_backend()
    )
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return priv_pem, pub_pem


def generate_ed25519_keypair() -> Tuple[Pem, Pem]:
    key = Ed25519PrivateKey.generate()

    priv_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    return priv_pem, pub_pem


def generate_keypair(
    kty: str,
    *,
    rsa_key_size: Optional[int] = None,
    ec_curve: Optional[str] = None,
) -> Tuple[str, str]:
    if kty == "rsa":
        return generate_rsa_keypair(rsa_key_size or 2048)
    elif kty == "ec":
        return generate_ec_keypair(ec_curve or "P-256")
    elif kty == "ed25519":
        return generate_ed25519_keypair()
    else:
        raise ValueError(f"Unsupported key type: {kty}")


def is_ssh_private_key(pem: str):
    return pem.startswith("-----BEGIN OPENSSH")


def ssh_private_key_to_pem(pem: str) -> Pem:
    priv = load_ssh_private_key(pem.encode("ascii"), None, default_backend())
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(
        "ascii"
    )
    return pem


def ssh_public_key_to_pem(ssh_pub_key: str) -> Pem:
    pub = load_ssh_public_key(ssh_pub_key.encode("ascii"), default_backend())
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return pem


def generate_cert(
    private_key_pem: Pem,
    issuer_cert_pem: Optional[Pem] = None,
    issuer_private_key_pem: Optional[Pem] = None,
    ca: bool = False,
    cn: Optional[str] = None,
):
    if not cn:
        cn = str(uuid4())
    subject_priv = load_pem_private_key(
        private_key_pem.encode("ascii"), None, default_backend()
    )
    subject_pub_key = subject_priv.public_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    if isinstance(subject_priv, Ed25519PrivateKey):
        hash_alg = None
    else:
        hash_alg = hashes.SHA256()

    if issuer_cert_pem:
        issuer = load_pem_x509_certificate(issuer_cert_pem.encode("ascii")).subject
    else:
        issuer = subject

    if issuer_private_key_pem:
        issuer_priv_key = load_pem_private_key(
            issuer_private_key_pem.encode("ascii"), None, default_backend()
        )
    else:
        issuer_priv_key = subject_priv
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_priv_key, hash_alg, default_backend())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def get_priv_key_type(priv_pem: str) -> str:
    key = load_pem_private_key(priv_pem.encode("ascii"), None, default_backend())
    if isinstance(key, RSAPrivateKey):
        return "rsa"
    elif isinstance(key, EllipticCurvePrivateKey):
        return "ec"
    elif isinstance(key, Ed25519PrivateKey):
        return "ed25519"
    raise NotImplementedError("unsupported key type")


def get_pub_key_type(pub_pem: str) -> str:
    key = load_pem_public_key(pub_pem.encode("ascii"), default_backend())
    if isinstance(key, RSAPublicKey):
        return "rsa"
    elif isinstance(key, EllipticCurvePublicKey):
        return "ec"
    elif isinstance(key, Ed25519PublicKey):
        return "ed25519"
    raise NotImplementedError("unsupported key type")


def get_cert_key_type(cert_pem: str) -> str:
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    if isinstance(cert.public_key(), RSAPublicKey):
        return "rsa"
    elif isinstance(cert.public_key(), EllipticCurvePublicKey):
        return "ec"
    raise NotImplementedError("unsupported key type")


def get_cert_info(pem: str) -> dict:
    cert = load_pem_x509_certificate(pem.encode("ascii"), default_backend())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return {"cn": cn}


def get_cert_fingerprint(pem: Pem) -> str:
    cert = load_pem_x509_certificate(pem.encode("ascii"), default_backend())
    return cert.fingerprint(hashes.SHA256()).hex()


def pub_key_pem_to_der(pem: Pem) -> bytes:
    pub_key = load_pem_public_key(pem.encode("ascii"), default_backend())
    return pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def pub_key_pem_to_ssh(pem: Pem) -> str:
    pub_key = load_pem_public_key(pem.encode("ascii"), default_backend())
    return pub_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


def private_key_pem_to_ssh(pem: Pem) -> str:
    private_key = load_pem_private_key(pem.encode("ascii"), None, default_backend())
    return private_key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    ).decode("ascii")


def cert_pem_to_der(pem: Pem) -> bytes:
    cert = load_pem_x509_certificate(pem.encode("ascii"), default_backend())
    return cert.public_bytes(Encoding.DER)


def cert_der_to_pem(der: bytes) -> str:
    cert = load_der_x509_certificate(der, default_backend())
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def create_jwt(body_claims: dict, key_priv_pem: str, key_id: str) -> str:
    return jwt.encode(
        body_claims, key_priv_pem, algorithm="RS256", headers={"kid": key_id}
    )


def create_jwks(cert_pem: str, kid: str):
    der_b64 = base64.b64encode(cert_pem_to_der(cert_pem)).decode("ascii")
    return {"keys": [{"kty": "RSA", "kid": kid, "x5c": [der_b64]}]}


def default_algorithm_for_key(key) -> str:
    """
    Get the default algorithm for a given key, based on its
    type and parameters.
    """

    if isinstance(key, (RSAPublicKey, RSAPrivateKey)):
        return "PS256"

    elif isinstance(key, (EllipticCurvePublicKey, EllipticCurvePrivateKey)):
        if isinstance(key.curve, ec.SECP256R1):
            return "ES256"
        elif isinstance(key.curve, ec.SECP384R1):
            return "ES384"
        elif isinstance(key.curve, ec.SECP521R1):
            return "ES512"
        else:
            raise NotImplementedError("unsupported curve")

    elif isinstance(key, (Ed25519PublicKey, Ed25519PrivateKey)):
        return "EdDSA"
    else:
        raise NotImplementedError(f"unsupported key type: {type(key)}")


def default_algorithm_for_private_key(key_pem: Pem) -> str:
    key = load_pem_private_key(key_pem.encode("ascii"), None, default_backend())
    return default_algorithm_for_key(key)


def verify_cose_sign1(buf: bytes, cert_pem: str):
    key_type = get_cert_key_type(cert_pem)
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    key = cert.public_key()
    if key_type == "rsa":
        cose_key = from_cryptography_rsakey_obj(key)
    else:
        cose_key = from_cryptography_eckey_obj(key)
    msg = Sign1Message.decode(buf)
    msg.key = cose_key
    if not msg.verify_signature():
        raise ValueError("signature is invalid")


def cose_header_to_jws_header(cose_header: dict) -> dict:
    jws_header = {}
    transforms = {
        # registered
        "ALG": ("alg", lambda v: v.fullname),
        "KID": ("kid", lambda v: v.decode("utf-8")),
        "CONTENT_TYPE": ("cty", None),
        "X5_CHAIN": ("x5c", lambda v: [base64.b64encode(c).decode() for c in v]),
    }
    for k, v in cose_header.items():
        try:
            k = k.fullname
        except AttributeError:
            pass
        if k in transforms:
            k, f = transforms[k]
            if f is not None:
                v = f(v)
        jws_header[k] = v
    return jws_header


def parse_cose_sign1(buf: bytes) -> Tuple[dict, bytes]:
    msg = Sign1Message.decode(buf)
    header = cose_header_to_jws_header(msg.phdr)
    payload = msg.payload
    return header, payload


def pretty_cose_sign1(buf: bytes) -> str:
    header, payload = parse_cose_sign1(buf)
    try:
        claims = json.loads(payload)
    except json.JSONDecodeError:
        claims = f"<{len(payload)} bytes>"
    try:
        return (
            "COSE_Sign1(\nheader="
            + json.dumps(header, indent=2)
            + "\npayload="
            + json.dumps(claims, indent=2)
            + "\n<signature>)"
        )
    except TypeError:
        print(header)
        raise


# temporary, from https://github.com/BrianSipos/pycose/blob/rsa_keys_algs/cose/keys/rsa.py
# until https://github.com/TimothyClaeys/pycose/issues/44 is implemented
def from_cryptography_rsakey_obj(ext_key) -> RSAKey:
    """
    Returns an initialized COSE Key object of type RSAKey.
    :param ext_key: Python cryptography key.
    :return: an initialized RSA key
    """

    def to_bstr(dec):
        blen = (dec.bit_length() + 7) // 8
        return dec.to_bytes(blen, byteorder="big")

    if hasattr(ext_key, "private_numbers"):
        priv_nums = ext_key.private_numbers()
        pub_nums = priv_nums.public_numbers
    else:
        priv_nums = None
        pub_nums = ext_key.public_numbers()

    cose_key = {}
    if pub_nums:
        cose_key.update(
            {
                RSAKpE: to_bstr(pub_nums.e),
                RSAKpN: to_bstr(pub_nums.n),
            }
        )
    if priv_nums:
        cose_key.update(
            {
                RSAKpD: to_bstr(priv_nums.d),
                RSAKpP: to_bstr(priv_nums.p),
                RSAKpQ: to_bstr(priv_nums.q),
                RSAKpDP: to_bstr(priv_nums.dmp1),
                RSAKpDQ: to_bstr(priv_nums.dmq1),
                RSAKpQInv: to_bstr(priv_nums.iqmp),
            }
        )
    return RSAKey.from_dict(cose_key)


def from_cryptography_eckey_obj(ext_key) -> EC2Key:
    """
    Returns an initialized COSE Key object of type EC2Key.
    :param ext_key: Python cryptography key.
    :return: an initialized EC key
    """
    if hasattr(ext_key, "private_numbers"):
        priv_nums = ext_key.private_numbers()
        pub_nums = priv_nums.public_numbers
    else:
        priv_nums = None
        pub_nums = ext_key.public_numbers()

    # Create map of cryptography curves to cose curves. E.g. {ec.SECP256R1: P256, ...}
    registered_crvs = {crv.curve_obj: crv for crv in REGISTERED_EC_CURVES.values()}
    if type(pub_nums.curve) not in registered_crvs:
        raise ValueError(f"Unsupported EC Curve: {type(pub_nums.curve)}")
    curve = registered_crvs[type(pub_nums.curve)]

    cose_key = {}
    if pub_nums:
        cose_key.update(
            {
                EC2KpCurve: curve,
                EC2KpX: pub_nums.x.to_bytes(curve.size, "big"),
                EC2KpY: pub_nums.y.to_bytes(curve.size, "big"),
            }
        )
    if priv_nums:
        cose_key.update(
            {
                EC2KpD: priv_nums.private_value.to_bytes(curve.size, "big"),
            }
        )
    return EC2Key.from_dict(cose_key)


def from_cryptography_ed25519key_obj(ext_key) -> OKPKey:
    """
    Returns an initialized COSE Key object of type OKPKey.
    :param ext_key: Python cryptography key.
    :return: an initialized OKP key
    """
    if isinstance(ext_key, Ed25519PrivateKey):
        priv_bytes = ext_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        pub_bytes = ext_key.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
    else:
        assert isinstance(ext_key, Ed25519PublicKey)
        priv_bytes = None
        pub_bytes = ext_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    curve = Ed25519

    cose_key = {}
    cose_key.update(
        {
            OKPKpCurve: curve,
            OKPKpX: pub_bytes,
        }
    )
    if priv_bytes:
        cose_key.update(
            {
                OKPKpD: priv_bytes,
            }
        )
    return OKPKey.from_dict(cose_key)


def cose_private_key_from_pem(pem: Pem):
    key = load_pem_private_key(pem.encode("ascii"), None, default_backend())
    if isinstance(key, RSAPrivateKey):
        return from_cryptography_rsakey_obj(key)
    elif isinstance(key, EllipticCurvePrivateKey):
        return from_cryptography_eckey_obj(key)
    elif isinstance(key, Ed25519PrivateKey):
        return from_cryptography_ed25519key_obj(key)
    raise NotImplementedError("unsupported key type")


def b64url(b: bytes) -> str:
    return base64.b64encode(b, altchars=b"-_").decode("ascii")


def sha256_file(path: Path) -> str:
    content = open(path, "rb").read()
    sha256 = hashlib.sha256(content).hexdigest()
    return sha256


def embed_receipt_in_cose(buf: bytes, receipt: bytes) -> bytes:
    # Need to parse the receipt to avoid wrapping it in a bstr.
    parsed_receipt = cbor2.loads(receipt)

    outer = cbor2.loads(buf)
    if hasattr(outer, "tag"):
        assert outer.tag == 18  # COSE_Sign1
        val = outer.value
    else:
        val = outer
    [_, uhdr, _, _] = val
    key = COSE_HEADER_PARAM_SCITT_RECEIPTS
    if key not in uhdr:
        uhdr[key] = []
    uhdr[key].append(parsed_receipt)
    return cbor2.dumps(outer)


def verify_cose_with_receipt(
    buf: bytes, service_trust_store: dict, receipt: Optional[bytes] = None
) -> None:
    msg = CoseMessage.decode(buf)
    assert isinstance(msg, Sign1Message)

    if receipt is None:
        parsed_receipts = msg.uhdr[COSE_HEADER_PARAM_SCITT_RECEIPTS]
        # For now, assume there is only one receipt
        assert len(parsed_receipts) == 1
        parsed_receipt = parsed_receipts[0]
    else:
        parsed_receipt = cbor2.loads(receipt)

    decoded_receipt = Receipt.from_cose_obj(parsed_receipt)

    service_id = decoded_receipt.phdr["service_id"]
    service_params = get_service_parameters(service_id, service_trust_store)
    decoded_receipt.verify(msg, service_params)


def load_private_key(key_path: Path) -> Pem:
    with open(key_path) as f:
        key_priv_pem = f.read()
    if is_ssh_private_key(key_priv_pem):
        key_priv_pem = ssh_private_key_to_pem(key_priv_pem)
    return key_priv_pem


def create_did_document(
    did: str, pub_key_pem: Pem, alg: Optional[str] = None, kid: Optional[str] = None
) -> dict:

    pub_key = load_pem_public_key(pub_key_pem.encode("ascii"), default_backend())
    der = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    if isinstance(pub_key, RSAPublicKey):
        pub_nums = pub_key.public_numbers()

        def encode_pub_num_jwk(dec):
            blen = (dec.bit_length() + 7) // 8
            b = dec.to_bytes(blen, byteorder="big")
            return base64.urlsafe_b64encode(b).decode("ascii")

        jwk = {
            "kty": "RSA",
            "n": encode_pub_num_jwk(pub_nums.n),
            "e": encode_pub_num_jwk(pub_nums.e),
        }

    elif isinstance(pub_key, Ed25519PublicKey):
        x = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(x).decode("ascii"),
        }

    elif isinstance(pub_key, EllipticCurvePublicKey):
        pub_numbers = pub_key.public_numbers()
        curve = pub_numbers.curve
        # Create map of curves to names. E.g. {ec.SECP256R1: "P-256", ...}
        registered_crvs = {
            crv.curve_obj: name for name, crv in REGISTERED_EC_CURVES.items()
        }
        if type(curve) not in registered_crvs:
            raise ValueError(f"Unsupported EC Curve: {curve}")
        crv_name = registered_crvs[type(curve)]
        x = pub_numbers.x.to_bytes(REGISTERED_EC_CURVES[crv_name].size, "big")
        y = pub_numbers.y.to_bytes(REGISTERED_EC_CURVES[crv_name].size, "big")

        jwk = {
            "kty": "EC",
            "crv": crv_name,
            "x": base64.urlsafe_b64encode(x).decode("ascii"),
            "y": base64.urlsafe_b64encode(y).decode("ascii"),
        }
    else:
        raise ValueError("unsupported key type")

    if kid is None:
        kid = hashlib.sha256(der).hexdigest()
    if alg is None:
        alg = default_algorithm_for_key(pub_key)

    jwk.update(
        {
            "kid": kid,
            "alg": alg,
        }
    )

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "assertionMethod": [
            {
                "id": f"{did}#{kid}",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
    }


class Signer:
    private_key: Pem
    issuer: Optional[str]
    kid: Optional[str]
    algorithm: str
    x5c: Optional[list]

    def __init__(
        self,
        private_key: Pem,
        issuer: Optional[str] = None,
        kid: Optional[str] = None,
        algorithm: Optional[str] = None,
        x5c: Optional[str] = None,
    ):
        """
        If no algorithm is specified, a sensible default is inferred from the private key.
        """

        self.private_key = private_key
        self.issuer = issuer
        self.kid = kid
        self.algorithm = algorithm or default_algorithm_for_private_key(private_key)
        self.x5c = x5c


def sign_claimset(
    signer: Signer,
    claims: bytes,
    content_type: str,
    feed: Optional[str] = None,
    registration_info: RegistrationInfo = {},
) -> bytes:
    headers = {}
    headers[pycose.headers.Algorithm] = signer.algorithm
    headers[pycose.headers.ContentType] = content_type

    if signer.x5c is not None:
        headers[pycose.headers.X5chain] = [cert_pem_to_der(x5) for x5 in signer.x5c]
    if signer.kid is not None:
        headers[pycose.headers.KID] = signer.kid.encode("utf-8")
    if signer.issuer is not None:
        headers[COSE_HEADER_PARAM_ISSUER] = signer.issuer
    if feed is not None:
        headers[COSE_HEADER_PARAM_FEED] = feed
    if registration_info:
        headers[COSE_HEADER_PARAM_REGISTRATION_INFO] = registration_info

    msg = Sign1Message(phdr=headers, payload=claims)
    msg.key = cose_private_key_from_pem(signer.private_key)
    return msg.encode(tag=True)


def sign_json_claimset(
    signer: Signer,
    claims: json,
    content_type: str = "application/vnd.dummy+json",
    feed: Optional[str] = None,
) -> bytes:
    return sign_claimset(
        signer, json.dumps(claims).encode("ascii"), content_type=content_type, feed=feed
    )


def read_service_trust_store(path: Path) -> dict:
    store = {}
    for path in path.glob("**/*.json"):
        with open(path) as f:
            params = json.load(f)

        service_id = params.get("serviceId")
        if not isinstance(service_id, str) or not service_id:
            raise ValueError("serviceId must be a non-empty string")
        if service_id in store:
            raise ValueError(
                f"Duplicate service ID while reading trust store: {service_id}"
            )

        store[service_id] = params
    return store


def get_service_parameters(service_id: str, service_trust_store: dict) -> dict:
    if service_id not in service_trust_store:
        raise ValueError(f"Service ID not found in trust store: {service_id}")
    return service_trust_store[service_id]
