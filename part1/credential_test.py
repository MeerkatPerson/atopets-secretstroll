import pytest

from petrelic.multiplicative.pairing import G1, G2, G1Element

import hashlib

from typing import List, Tuple, Dict

from credential import generate_key, sign, verify

from keys import PublicKey, SecretKey

Signature = Tuple[G1Element, G1Element]

AttributeMap = Dict[str, int]

AnonymousCredential = Tuple[Signature, AttributeMap]

""" Test the functionality in credential.py (generate_key, sign, verify) """
'''
NOTE: tests of the entire protocol (1 successful and 2 unsuccessful 
            paths) can be found in protocol_test.py
'''


def test_generate_key() -> None:

    available_subscriptions: List[str] = ['restaurants', 'bars',
                                          'dojos', 'cinemas', 'zendos', 'gyms']

    username: str = 'zoé'

    attributes: List[str] = available_subscriptions + [username]

    res: Tuple[SecretKey, PublicKey] = generate_key(attributes)

    pk: PublicKey = res[0]

    sk: SecretKey = res[1]

    # Some assertions related to sk

    assert sk.x < G1.order()

    assert sk.x >= 0

    assert isinstance(sk.X, G1Element)

    assert sk.X == (G1.generator() ** sk.x)

    assert len(sk.y_list) == (len(attributes) + 1)

    # Some assertions related to pk

    assert pk.g == G1.generator()

    Y_list_compareto = list(map(lambda a: G1.generator() ** a, sk.y_list))

    assert pk.Y_list == Y_list_compareto

    assert pk.g_snake == G2.generator()

    Y_snake_list_compareto = list(
        map(lambda a: G2.generator() ** a, sk.y_list))

    assert pk.Y_snake_list == Y_snake_list_compareto

    assert pk.X_snake == G2.generator() ** sk.x


def test_sign() -> None:

    available_subscriptions: List[str] = ['restaurants', 'bars',
                                          'dojos', 'cinemas', 'zendos', 'gyms']

    username: str = 'zoé'

    attributes: List[str] = available_subscriptions + [username]

    res: Tuple[PublicKey, SecretKey] = generate_key(attributes)

    issuer_sk: SecretKey = res[1]

    chosen_subscriptions: List[int] = [1, 1, 1, 0, 0, 1]

    # Generate a user-keypair because apparently, we need to include a secret key
    # as user attribute
    user_keypair: Tuple[PublicKey, SecretKey] = generate_key(attributes)

    attribute_values = chosen_subscriptions + [int(
        hashlib.sha256(username.encode('utf-8')).hexdigest(), 16),
        int(hashlib.sha256(str(user_keypair[1]).encode('utf-8')).hexdigest(), 16)]

    signature: Signature = sign(issuer_sk, attribute_values)

    assert isinstance(signature[0], G1Element)

    assert isinstance(signature[1], G1Element)


def test_verify() -> None:

    available_subscriptions: List[str] = ['restaurants', 'bars',
                                          'dojos', 'cinemas', 'zendos', 'gyms']

    username: str = 'zoé'

    attributes: List[str] = available_subscriptions + [username]

    res: Tuple[PublicKey, SecretKey] = generate_key(attributes)

    issuer_sk: SecretKey = res[1]

    chosen_subscriptions: List[int] = [1, 1, 1, 0, 0, 1]

    # Generate a user-keypair because apparently, we need to include a secret key
    # as user attribute
    user_keypair: Tuple[PublicKey, SecretKey] = generate_key(attributes)

    attribute_values = chosen_subscriptions + [int(
        hashlib.sha256(username.encode('utf-8')).hexdigest(), 16),
        int(hashlib.sha256(str(user_keypair[1]).encode('utf-8')).hexdigest(), 16)]

    signature: Signature = sign(issuer_sk, attribute_values)

    pk: PublicKey = res[0]

    verification_res = verify(pk, signature, attribute_values)

    assert verification_res == True
