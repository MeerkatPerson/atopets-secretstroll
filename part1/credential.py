"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

import random
import re
from typing import Any, List, Tuple, Dict

from serialization import jsonpickle, G1EAHandler

from functools import reduce

import hashlib

from keys import SecretKey, PublicKey

from petrelic.multiplicative.pairing import G1, G2, G1Element

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!

# like [('username': 'zoé'),('subscriptions': ['gyms','restaurants','zendos']),...
AttributeMap = Dict[str, Any]

Signature = Tuple[G1Element, G1Element]

######################
## SIGNATURE SCHEME ##
######################


def generate_key(
    attributes: List[str]
) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

    # attributes = available (!) subscriptions + username + user_secret key

    # (1) Pick x, y_1, ... , y_L from Z_p uniformly at random

    p = G1.order()

    x = p.random()

    # attributes = 'available subscriptions' + the username + user_secret key
    y_list = [p.random() for i in range(len(attributes) + 1)]

    # (2) pick random generators g e G_1, (g~) e G_2 and compute:
    #     X1 = g1^x
    #     X2 = g2^x
    #     Y1_i = g_1^(y_i)
    #     Y2_i = g_2^(y_i)

    g = G1.generator()

    g_snake = G2.generator()

    X = g ** x

    X_snake = g_snake ** x

    Y_list = []
    Y_snake_list = []

    # attributes = 'available subscriptions' + the username + the user's secret key
    for i in range(len(attributes) + 1):

        Y_elem = g ** (y_list[i])
        Y_list = Y_list + [Y_elem]

        Y_snake_elem = g_snake ** (y_list[i])
        Y_snake_list = Y_snake_list + [Y_snake_elem]

    # (3) Output pk = (g1,Y1_1,...,Y1_L,(g~),(X~),(Y~)_1,...,(Y~)_L)
    #     as well as sk = (x,X,y_1,...,y_L)

    # have to slice because the last two attributes are 'username' and 'user_sk'
    pk = PublicKey(g, g_snake, Y_list, X_snake, Y_snake_list, attributes[:-1])

    sk = SecretKey(x, X, y_list)

    # public and private key
    return (pk, sk)


def sign(
    sk: SecretKey,
    msgs: List[int]
) -> Signature:
    """ Sign the vector of messages `msgs` """
    p = G1.order()
    h = G1.generator()

    while (h == G1.neutral_element()):
        h = G1.generator()

    prod_ = h ** sk.x

    for i in range(len(msgs)):
        prod_ = prod_ * (h ** (msgs[i]*sk.y_list[i]))

    return (h, prod_)


def verify(
    pk: PublicKey,
    signature: Signature,
    msgs: List[int]
) -> bool:
    """ Verify the signature on a vector of messages """

    mult = pk.X_snake

    msgs_Y_snake_list_zipped = list(zip(pk.Y_snake_list, msgs))

    Y_snake_list_pow_msgs = list(map(
        lambda a: a[0] ** a[1], msgs_Y_snake_list_zipped))

    Y_snake_list_pow_msgs_prod = reduce(
        lambda a, b: a * b, Y_snake_list_pow_msgs)

    mult = mult * Y_snake_list_pow_msgs_prod

    # print(signature[0].pair(mult))

    # print(signature[1].pair(pk.g_snake))

    return (signature[0].pair(mult) == signature[1].pair(pk.g_snake))

#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##
# see user.py and service_provider.py

## SHOWING PROTOCOL ##
# see user.py and service_provider.py
