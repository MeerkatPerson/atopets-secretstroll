
from credential_test import AnonymousCredential
import pytest

from petrelic.multiplicative.pairing import G1, G2, G1Element

from petrelic.bn import Bn

from typing import List, Tuple, Dict

from keys import PublicKey, SecretKey

from credential import generate_key

from user import User

from service_provider import ServiceProvider

# ---------------------------------------------------
# Type aliases

AttributeMap = Dict[str, int]

IssueRequest = Tuple[int, List[int], G1Element, str]

Signature = Tuple[G1Element, G1Element]

BlindSignature = Tuple[Signature, AttributeMap]

AnonymousCredential = Tuple[Signature, AttributeMap]

DisclosureProof = Tuple[Signature, AttributeMap, int]

""" Test the issuance & disclosure protocol functionality """

'''
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 (1) Successful run
'''


def test_ABC_protocol_success() -> None:

    # ---------------------------------------------------------------------------
    # (I.) Generate the credential

    available_subscriptions: List[str] = ['restaurants', 'gyms',
                                          'bars', 'cafés', 'zendos', 'libraries']

    username: str = 'zoé'

    attributes: List[str] = available_subscriptions + [username]

    # Generate a key pair for the issuer
    provider_pk, provider_sk = generate_key(attributes)

    print("keys generated")

    # create a user

    chosen_subscriptions = ['restaurants', 'gyms', 'cafés']

    user = User(provider_pk, chosen_subscriptions, 'zoé')

    # create an issue request
    issue_request = user.create_issue_request()

    # ----------------------------------------------------

    # assert that types are correct
    # issue_request = (c, s, com) = Tuple[int, list(int), G1Element]
    assert isinstance(issue_request[0], int)

    # ensure each element of the s-list is an integer mod p,
    # where p is the order of G1.
    for s_i in issue_request[1]:

        assert isinstance(s_i, Bn)

        assert s_i < G1.order()

    assert isinstance(issue_request[2], G1Element)

    # ----------------------------------------------------

    # create a service provider
    provider = ServiceProvider(
        provider_pk, provider_sk, chosen_subscriptions, username)

    # sign the issuance request
    res = provider.sign_issue_request(issue_request)

    assert isinstance(res, Tuple)

    # ---------------------------------------------------
    # Next, the user must unblind the signature

    credential = user.obtain_credential(res)

    # ---------------------------------------------------------------------------
    # (II.) Make a request

    message: bytes = (f"{46.52345},{6.57890}").encode("utf-8")

    disclosure_proof: DisclosureProof = user.create_disclosure_proof(
        credential, message)

    disclosure_res: bool = provider.verify_disclosure_proof(
        disclosure_proof, message)

    assert disclosure_res == True


'''
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 (2) Unsuccessful run 1: attempt to get signature for issue request
     computed with a pk different from the issuer pk (issuance protocol)
'''


def test_ABC_protocol_issuance_fail() -> None:

    # ---------------------------------------------------------------------------
    # (I.) Generate the credential

    available_subscriptions: List[str] = ['restaurants', 'gyms',
                                          'bars', 'cafés', 'zendos', 'libraries']

    username: str = 'zoé'

    attributes: List[str] = available_subscriptions + [username]

    # Generate a key pair for the issuer
    provider_pk, provider_sk = generate_key(attributes)

    print("keys generated")

    # create a user

    chosen_subscriptions = ['restaurants', 'gyms', 'cafés']

    # Generate another keypair to explore failure path

    # Generate a key pair for the issuer
    dupe_pk, dupe_sk = generate_key(attributes)

    user = User(dupe_pk, chosen_subscriptions, 'zoé')

    # create an issue request
    issue_request = user.create_issue_request()

    # ----------------------------------------------------

    # assert that types are correct
    # issue_request = (c, s, com) = Tuple[int, list(int), G1Element]
    assert isinstance(issue_request[0], int)

    # ensure each element of the s-list is an integer mod p,
    # where p is the order of G1.
    for s_i in issue_request[1]:

        assert isinstance(s_i, Bn)

        assert s_i < G1.order()

    assert isinstance(issue_request[2], G1Element)

    # ----------------------------------------------------

    # create a service provider
    provider = ServiceProvider(
        provider_pk, provider_sk, chosen_subscriptions, username)

    # sign the issuance request
    res = provider.sign_issue_request(issue_request)

    # FAIL: signature unsuccessful
    # assert isinstance(res, NoneType)
    assert res == None


'''
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
(3) Unsuccessful run 2: Attempt to verify using the wrong message
        (disclosure protocol) 
'''


def test_ABC_protocol_disclosure_fail() -> None:

    # ---------------------------------------------------------------------------
    # (I.) Generate the credential

    available_subscriptions: List[str] = ['restaurants', 'gyms',
                                          'bars', 'cafés', 'zendos', 'libraries']

    username: str = 'zoé'

    attributes: List[str] = available_subscriptions + [username]

    # Generate a key pair for the issuer
    provider_pk, provider_sk = generate_key(attributes)

    print("keys generated")

    # create a user

    chosen_subscriptions = ['restaurants', 'gyms', 'cafés']

    user = User(provider_pk, chosen_subscriptions, 'zoé')

    # create an issue request
    issue_request = user.create_issue_request()

    # ----------------------------------------------------

    # assert that types are correct
    # issue_request = (c, s, com) = Tuple[int, list(int), G1Element]
    assert isinstance(issue_request[0], int)

    # ensure each element of the s-list is an integer mod p,
    # where p is the order of G1.
    for s_i in issue_request[1]:

        assert isinstance(s_i, Bn)

        assert s_i < G1.order()

    assert isinstance(issue_request[2], G1Element)

    # ----------------------------------------------------

    # create a service provider
    provider = ServiceProvider(
        provider_pk, provider_sk, chosen_subscriptions, username)

    # sign the issuance request
    res = provider.sign_issue_request(issue_request)

    assert isinstance(res, Tuple)

    # ---------------------------------------------------
    # Next, the user must unblind the signature

    credential = user.obtain_credential(res)

    # ---------------------------------------------------------------------------
    # (II.) Make a request

    message: bytes = (f"{46.52345},{6.57890}").encode("utf-8")

    disclosure_proof: DisclosureProof = user.create_disclosure_proof(
        credential, message)

    wrong_message: bytes = (f"{46.62345},{6.47890}").encode("utf-8")

    # Attempt to verify using the wrong message => should fail
    disclosure_res: bool = provider.verify_disclosure_proof(
        disclosure_proof, wrong_message)

    assert disclosure_res == False
