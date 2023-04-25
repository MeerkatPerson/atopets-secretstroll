"""
Classes that you need to complete.
"""

from credential import generate_key

import jsonpickle

from typing import Any, Dict, List, Union, Tuple

from keys import PublicKey, SecretKey

from petrelic.multiplicative.pairing import G1, G1Element

# Optional import
from serialization import jsonpickle
from service_provider import ServiceProvider

from user import User

# Type aliases
State = User

Signature = Tuple[G1Element, G1Element]

IssueRequest = Tuple[int, List[int], G1Element, str]

AttributeMap = Dict[str, Any]

BlindSignature = Tuple[Signature, AttributeMap]

AnonymousCredential = Tuple[Signature, AttributeMap]

DisclosureProof = Tuple[Signature, AttributeMap, int]

# ***********************************************************************************


def serialize_object(object: Any) -> bytes:

    return jsonpickle.encode(object).encode('utf-8')


def deserialize_object(serialized_object: bytes) -> Any:

    return jsonpickle.decode(serialized_object.decode('utf-8'))


class Server:
    """Server"""

    # public key

    def __init__(self):
        """
        Server constructor.
        """

    @staticmethod
    def generate_ca(
        subscriptions: List[str]
    ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """

        # NOTE: we know that 'subscriptions' already contains the 'username' as its last element (it is added in server.py.server_setup)

        pk, sk = generate_key(subscriptions)

        pk_bytes: bytes = serialize_object(pk)  # serialize pk
        sk_bytes: bytes = serialize_object(sk)  # serialize sk

        return (sk_bytes, pk_bytes)

    def process_registration(
        self,
        server_sk: bytes,
        server_pk: bytes,
        issuance_request: bytes,
        username: str,
        subscriptions: List[str]
    ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """

        # Restore server_pk, server_sk, and issuance_request from
        # bytes
        server_pk_restored: PublicKey = deserialize_object(server_pk)

        server_sk_restored: SecretKey = deserialize_object(server_sk)

        issuance_request_restored: IssueRequest = deserialize_object(
            issuance_request)

        # Initialize ServiceProvider
        self.service_provider = ServiceProvider(
            server_pk_restored, server_sk_restored, subscriptions, username)

        # Sign the issuance request
        blind_signature: BlindSignature = self.service_provider.sign_issue_request(
            issuance_request_restored)

        # Serialize the blind signature & return
        blind_signature_bytes: bytes = serialize_object(blind_signature)

        return blind_signature_bytes

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        # reconstruct the server pk from bytes
        server_pk_reconstructed: PublicKey = deserialize_object(server_pk)

        # deserialize the DisclosureProof
        disclosure_proof_reconstructed: DisclosureProof = deserialize_object(
            signature)

        # create a service provider object
        service_provider: ServiceProvider = ServiceProvider(
            server_pk_reconstructed, None, revealed_attributes, 'ANON')

        return service_provider.verify_disclosure_proof(disclosure_proof_reconstructed, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """

    def prepare_registration(
        self,
        server_pk: bytes,
        username: str,
        subscriptions: List[str]
    ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's (!!!) subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """

        # reconstruct the server pk from bytes
        server_pk_reconstructed: PublicKey = deserialize_object(server_pk)

        # Now we want to create an issuance request.
        # Firstly, we need to create a user object. To do this, we need
        # - the server's public key
        # - the user's chosen subscriptions
        # - the username
        user: User = User(server_pk_reconstructed, subscriptions, username)

        # Create an issue_request: (c, s_l, com, username)
        issue_request: IssueRequest = user.create_issue_request()

        # Serialize the issue request
        issue_req_serialized = serialize_object(issue_request)

        # For now, let's assume we are using the user-object to transmit state
        return (issue_req_serialized, user)

    def process_registration_response(
        self,
        server_pk: bytes,
        server_response: bytes,
        private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        # reconstruct the blind signature that has been received from the server
        blind_signature: BlindSignature = deserialize_object(server_response)

        # State = User object, create an attribute-based credential for the user
        user: User = private_state

        credential: AnonymousCredential = user.obtain_credential(
            blind_signature)

        # Serialize credential
        credential_serialized: bytes = serialize_object(credential)

        return credential_serialized

    def sign_request(
        self,
        server_pk: bytes,
        credentials: bytes,
        message: bytes,
        types: List[str]  # may be a subset of subscriptions
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """

        # reconstruct the server pk from bytes
        server_pk_reconstructed: PublicKey = deserialize_object(server_pk)

        # reconstruct the anonymous credential from bytes
        credentials_deserialized: AnonymousCredential = deserialize_object(
            credentials)

        user: User = User(issuer_pk=server_pk_reconstructed,
                          subscriptions=types)

        # Make a disclosure proof
        disclosure_proof: DisclosureProof = user.create_disclosure_proof(
            credentials_deserialized, message)

        return serialize_object(disclosure_proof)
