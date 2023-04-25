
from typing import Any, List, Tuple, Dict

from petrelic.multiplicative.pairing import G1, G1Element

from keys import SecretKey, PublicKey

import pickle

import hashlib

from functools import reduce

from credential import sign, verify

# ***********************************************************************************
# Set type aliases

AttributeMap = Dict[str, Any]

# In order to request a certificate, the user provides:
# * c, a hash
# * s, a list containing s_t, s_(a_1), ... , s_(a_L)
# * com, an element of group G1

IssueRequest = Tuple[int, List[int], G1Element]

Signature = Tuple[G1Element, G1Element]

BlindSignature = Tuple[Signature, AttributeMap]

DisclosureProof = Tuple[Signature, AttributeMap, int]

# ***********************************************************************************


class ServiceProvider:

    'Class for representing a service provider in SecretStroll'

    def __init__(self, pk: PublicKey, sk: SecretKey, subscriptions: List[str], username: str):

        self.pk: PublicKey = pk

        self.sk: SecretKey = sk

        self.issuer_attributes: AttributeMap = {'username': username}

        self.user_attributes: AttributeMap = {}

        # Create the user_attribute-dict by matching available to chosen subscriptions
        for elem in pk.available_subscriptions:

            # if this item from the list of AVAILABLE subscriptions stored in the server's pk
            # is also contained in the list of CHOSEN subscriptions, the value of this attribute
            # will be 1
            if elem in subscriptions:

                self.user_attributes.update({elem: 1})

            # if this item from the list of AVAILABLE subscriptions stored in the server's pk
            # is NOT contained in the list of CHOSEN subscriptions, the value of this attribute
            # will be 0
            else:

                self.user_attributes.update({elem: 0})

        self.user_attributes.update({'user_sk': 'dummy'})

    def sign_issue_request(
        self,
        request: IssueRequest,
    ) -> BlindSignature:
        """ Create a signature corresponding to the user's request

        This corresponds to the "Issuer signing" step in the issuance protocol.
        """

        # NOTE found out what the issuer_attributes are. There is just one. It is 'username'. Obvious, huh?

        # ******************************************************************************
        # (I.) Verify the proof

        # grab the Y_i corresponding to the user attributes from the pk (the last element of pk.Y_list corresponds to the username,
        # which is an issuer attribute, not a user attribute)
        Y_list = self.pk.Y_list[:-1]

        # grab s_l from the request: [(r_1 - c*0) mod p, (r_2 - c*1) mod p, ... , (r_L - c*1) mod p]
        s_l = request[1][1:]

        # = [(Y_1,(r_1 - c*0) mod p), (Y_2, (r_2 - c*1) mod p), ... , (Y_L, (r_L - c*1) mod p)]
        s_l_y_zip = list(zip(Y_list, s_l))

        # = [Y_1^((r_1 - c*0) mod p), Y_2^((r_2 - c*1) mod p), ... , Y_L^((r_L - c*1) mod p)]
        s_l_y_pow = list(map(lambda a: a[0] ** a[1], s_l_y_zip))

        # the product of all the elements of the list
        s_l_y_pow_prod = reduce(lambda a, b: a * b, s_l_y_pow)

        # Reconstruct R (R')

        R_prime = (request[2] ** request[0]) * \
            (self.pk.g ** request[1][0]) * s_l_y_pow_prod

        # Reconstruct c (c')

        hash_input = str(self.pk.g) + str(Y_list) + str(request[2]) + \
            str(R_prime)

        c_prime = int(hashlib.sha256(hash_input.encode('utf-8')
                                     ).hexdigest(), 16)

        # Verify that c == c'

        if request[0] != c_prime:
            print("C IS NOT EQUAL")
            return

        # ******************************************************************************
        # (II.) Create the signature

        # NOTE Realization: wanted to use the 'sign' function from credential.py.
        #                   Turned out I can't, because what the user does in the
        #                   'unblinding signature' step actually transforms the
        #                   sigma' - signature computed in step 5 of the issuance
        #                   protocol into a signature of the form stated in the 'sign'-
        #                   function in credential.py (assuming h = g**u)
        #                   Another option is to leave the transformation step in
        #                   the 'unblinding signature' step out.

        # -----------------------------------------------------------------------------------------
        # OPTION 1: use the 'sign' function.

        '''

        # It has turned out that the server has just a single attribute, which is the user name.
        # We want to use its value in an exponent, hence we hash it to transform it into an integer.

        username_hashed = int(hashlib.sha256(
            self.issuer_attributes['username'].encode('utf-8')).hexdigest(), 16)

        # Grab ALL attributes
        all_attributes_values = list(self.user_attributes.values()) + [
            username_hashed]

        print("all_attributes_values: ")

        print(all_attributes_values)

        # Map to bytes so the attribute list can be passed to 'sign' (credential.py)
        # Not currently doing this because we are apparently allowed to change that part of the API as we see fit
        
        # all_attributes_values_bytes = list(
        #    map(lambda a: pickle.dumps(a), all_attributes_values))

        # generate signature
        signature: Signature = sign(self.sk, all_attributes_values)

        '''

        # -----------------------------------------------------------------------------------------
        # OPTION 2: use the formula specified in 'issuer signing' (step 5 of the issuance protocol)

        p = G1.order()

        u = p.random()

        # Compute sigma_prime:

        # We only have one issuer attribute, which makes stuff reasonably simple

        L = len(self.pk.Y_list)

        Y_issuer = self.pk.Y_list[L-1]

        username_hashed = int(hashlib.sha256(
            self.issuer_attributes['username'].encode('utf-8')).hexdigest(), 16)

        Y_msg_pow = Y_issuer ** username_hashed

        sigma_prime_1 = self.pk.g ** u

        sigma_prime_2 = (self.sk.X * request[2] * Y_msg_pow) ** u

        signature: Signature = (sigma_prime_1, sigma_prime_2)

        return (signature, self.issuer_attributes)

        # *********************************************************************************
        ## SHOWING PROTOCOL ##

    def verify_disclosure_proof(
        self,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
        """ Verify the disclosure proof

        Hint: The verifier may also want to retrieve the disclosed attributes
        """

        sigma_prime = disclosure_proof[0]

        if sigma_prime[0] == G1.neutral_element():

            return 

        disclosed_attributes = disclosure_proof[1]

        # Grab the Y_i's corresponding to the disclosed attributes (the subscriptions)
        rhs = sigma_prime[1].pair(self.pk.g_snake) / \
            sigma_prime[0].pair(self.pk.X_snake)

        # iterate all the way through the available subscriptions
        # and check which ones are among the disclosed attributes;
        # order matters!!!
        for ind, value in enumerate(self.pk.available_subscriptions):

            if value in list(disclosed_attributes.keys()):

                # If this element from the list of available subscriptions is
                # in fact among the disclosed attributes, grab the corresponding
                # Y_snake_i from the Y_snake_list and pair it up with sigma_prime_1 (= sigma_prime[0])

                pair = sigma_prime[0].pair(self.pk.Y_snake_list[ind])

                # raise that pair to the power of the respective disclosed attribute's value

                pair_pow = pair ** (-disclosed_attributes[value])

                # include in the product

                rhs = rhs * pair_pow

        hash_input = str(self.pk.g_snake) + str(rhs) + \
            str(self.pk.Y_snake_list) + str(message)

        c_prime = int(hashlib.sha256(
            hash_input.encode('utf-8')).hexdigest(), 16)

        # print(f'c_prime server side: {c_prime}')

        if c_prime != disclosure_proof[2]:

            return False

        return True
