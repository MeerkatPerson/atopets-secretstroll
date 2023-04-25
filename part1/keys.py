
from re import X
from typing import List, Tuple, Dict

from petrelic.multiplicative.pairing import G1, G2, G1Element, G2Element


class SecretKey:

    'Class for representing a secret key in the PS signature scheme'

    def __init__(self, x: int, X: G1Element, y_list: List[int]):
        self.x = x
        self.X = X
        self.y_list = y_list


class PublicKey:

    'Class for representing a public key in the PS signature scheme'

    def __init__(self,
                 g: G1Element,
                 g_snake: G2Element,
                 Y_list: List[G1Element],
                 X_snake: G2Element,
                 Y_snake_list: List[G2Element],
                 available_subscriptions: List[str]):
        self.g: G1Element = g
        self.g_snake = g_snake
        self.Y_list: List[G1Element] = Y_list
        self.X_snake: G2Element = X_snake
        self.Y_snake_list: List[G2Element] = Y_snake_list
        self.available_subscriptions = available_subscriptions
