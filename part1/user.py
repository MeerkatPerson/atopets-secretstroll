

from typing import Any, List, Tuple, Dict

from pkg_resources import AvailableDistributions

from petrelic.multiplicative.pairing import G1, G1Element

from keys import SecretKey, PublicKey

import hashlib

from functools import reduce

from credential import generate_key, verify

# importing operator for operator functions
import operator

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

AnonymousCredential = Tuple[Signature, AttributeMap]

DisclosureProof = Tuple[Signature, AttributeMap, int]

# ***********************************************************************************


class User:

    'Class for representing a user of SecretStroll'

    def __init__(self, issuer_pk: PublicKey, subscriptions: List[str], username: str = 'ANON'):

        self.issuer_pk = issuer_pk      # NOTE the public key is the server's, not the user's

        self.t: int = 0   # a random value drawn from Z_p that will be set in create_issue_request

        self.username: str = username

        self.user_attributes: AttributeMap = {}

        # In the project handout, Pt. 1.3 'Integrating ABcs into # SecretStroll', we find that: 'a common ABC practice is to include
        # a secret key in the credential as an attribute'
        # Thus, let's generate a key-pair for the user
        self.user_sk = generate_key(
            self.issuer_pk.available_subscriptions + [username])[1]  # generate a secret key

        # Create the user_attribute-dict by matching available to chosen subscriptions
        for elem in issuer_pk.available_subscriptions:

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

        # add the hashed sk to the user_attributes
        sk_hashed = int(hashlib.sha256(str(self.user_sk).encode('utf-8')
                                       ).hexdigest(), 16)
        self.user_attributes.update({'user_sk': sk_hashed})

        self.hidden_attributes: AttributeMap = {}
        self.disclosed_attributes: AttributeMap = {}

    # *********************************************************************************
    ## ISSUANCE PROTOCOL ##

    def create_issue_request(self) -> IssueRequest:
        """ Create an issuance request

        This corresponds to the "user commitment" step in the issuance protocol.

        *Warning:* You may need to pass state to the `obtain_credential` function.
        """

        # grab the generator of G1 from pk.
        g_1 = self.issuer_pk.g

        p = G1.order()                  # type of result is a Bn large integer

        self.t = p.random()             # grab a number from Z_p uniformly at random

        L = len(self.user_attributes)   # grab the number of attributes

        # ******************************************************************************

        # Get the product of all the Y_i^(alpha_i)'s (hopefully)
        # & compute the commitment (com)

        # (a) get the Y_i's from pk

        # have to slice because one of the Y_i 's represents username, which
        # is not a user_attribute, but an issuer_attribute
        Y_list = self.issuer_pk.Y_list[:-1]

        # print(f'Length of Y_list in create_issuance_request: {len(Y_list)}')

        # (b) create a list of the form [(Y_1, 1), (Y_2, 0), ... ,(Y_n,1)]

        # grab the user attributes' values as a list
        user_attribute_values_list = list(self.user_attributes.values())

        # print(f'User attribute values: {user_attribute_values_list}')

        attribute_vals = list(zip(Y_list, user_attribute_values_list))

        # (c) create a list of the form [Y_1^0, Y_2^1, ..., Y_n^1]

        attributes_mapped = list(
            map(lambda a: (a[0]**a[1]), attribute_vals))

        # (d) Multiply all the list elements together

        attribute_product = reduce(operator.mul, attributes_mapped)

        # multiply together to obtain commitment
        com = (g_1 ** self.t) * attribute_product

        # ******************************************************************************
        # Next we will generate a non-interactive version of our sigma-protocol,
        # proving knowledge of our attributes (= subscriptions)

        # (a) Generate L + 1 random values,
        #     one corresponding to the random element t e Z_p generated previously
        #     and L more for the attributes:

        r_t = p.random()

        r_l = [p.random() for i in range(L)]

        # = [(Y_1, r_(a_1)), (Y_2, r_(a_2)), ... , (Y_L, r_(a_L))]
        y_r_l_zip = list(zip(Y_list, r_l))

        # = [Y_1^(r_(a_1)), Y_2^(r_(a_2)), ... , Y_L^(r_(a_L))]
        y_pow_r_l = list(map(lambda a: (a[0]**a[1]), y_r_l_zip))

        # = the product of all the Y_i^(r_(a_i))'s
        y_pow_r_l_prod = reduce(operator.mul, y_pow_r_l)

        # (b) Now we have everything ready to compute R, which would be the first thing sent
        #     by Peggy to Victor in an interactive version of the proof

        R = (g_1 ** r_t) * y_pow_r_l_prod

        # (c) Compute a hash of all publicly known information (generator of G1, the commitment, Y_1, ... , Y_L, R, and the username (= m here)).
        #     This hash will replace the challenge from the interactive sigma protocol.

        hash_input = str(g_1) + str(Y_list) + str(com) + \
            str(R)

        # print(f"hash client: {hash_input}")

        c = int(hashlib.sha256(hash_input.encode('utf-8')
                               ).hexdigest(), 16)

        # (d) Generate L + 1 responses

        s_t = (r_t - c * self.t) % p

        # = [(r_1, 0),(r_2,1),...,(r_L,1)]
        s_r_l = list(zip(r_l, user_attribute_values_list))

        # = [(r_1 - c*0)) mod p, (r_2 - c*1) mod p, ... , (r_L - c*1) mod p]
        s_l = [(elem[0] - c*elem[1]) % p for elem in s_r_l]

        # = [(r_t - c*t) mod p, (r_1 - c*0) mod p, (r_2 - c*1) mod p, ... , (r_L - c*0) mod p

        s_l = [s_t] + s_l

        # print(s_l)

        # Send: c, (s_t, s_(a_1), ... , s_(a_n)), com

        issue_request = (c, s_l, com)

        return issue_request

    def obtain_credential(
        self,
        response: BlindSignature
    ) -> AnonymousCredential:
        """ Derive a credential from the issuer's response

        This corresponds to the "Unblinding signature" step.
        """

        # Grab the two components of the BlindSignature: signature + issuer_credentials

        signature: Signature = response[0]

        issuer_attributes: AttributeMap = response[1]

        # Issuer attributes are now hidden attributes (we don't disclose them when making a request
        # in the disclosure protocol)
        self.hidden_attributes = issuer_attributes

        sigma_1 = signature[0]

        sigma_2 = signature[1]/(signature[0] ** self.t)

        signature_unblinded: Signature = (sigma_1, sigma_2)

        # Check validity of signature
        # Grab ALL attributes

        username_hashed = int(hashlib.sha256(
            issuer_attributes['username'].encode('utf-8')).hexdigest(), 16)

        user_attributes_values = list(self.user_attributes.values())

        all_attributes_values = user_attributes_values + [username_hashed]

        # Verify the validity of the signature
        if verify(self.issuer_pk, signature_unblinded, all_attributes_values) == False:

            return

        # Create a dict containing all attributes (user [= subscriptions] + issuer [ = username])
        all_attributes_dict: AttributeMap = {}

        all_attributes_dict.update(self.user_attributes)

        all_attributes_dict.update(issuer_attributes)

        # return signature + all attributes (user + issuer)
        return (signature_unblinded, all_attributes_dict)

    # *********************************************************************************
    ## SHOWING PROTOCOL ##

    def create_disclosure_proof(
        self,
        credential: AnonymousCredential,
        message: bytes
    ) -> DisclosureProof:
        """ Create a disclosure proof """

        # create some random numbers

        p = G1.order()

        r = p.random()

        t = p.random()  # caution: this is another t than the one in the issuance protocol (see lecture notes)

        # compute randomized signature

        signature = credential[0]

        sigma_prime = (signature[0] ** r,
                       (signature[1] * (signature[0] ** t)) ** r)

        # At this point, the user_attributes are only the types of subscriptions the user
        # has utilized in making their query

        attributes = credential[1]

        # First part of the commitment is e(sigma_prime_1, g_snake)^t

        pair = sigma_prime[0].pair(self.issuer_pk.g_snake)

        pair_pow_t = pair ** t

        com = pair_pow_t

        # need an index to be able to access Y_snake_list

        ind = 0

        for key, value in attributes.items():

            if key == 'username':

                username_hashed = int(hashlib.sha256(
                    value.encode('utf-8')).hexdigest(), 16)

                pair = sigma_prime[0].pair(self.issuer_pk.Y_snake_list[ind])

                pair_pow_attr = pair ** username_hashed

                com = com * pair_pow_attr

            else:

                # Check if the attribute is disclosed or not (note that we initialized the
                # current instance of 'User' only using the attributes that were included in the query,
                # i.e. (user_attributes[k] == 1) => attribute k was disclosed in the query)

                if self.user_attributes[key] == 1:

                    self.disclosed_attributes.update({key: value})

                else:

                    pair = sigma_prime[0].pair(
                        self.issuer_pk.Y_snake_list[ind])

                    pair_pow_attr = pair ** value

                    com = com * pair_pow_attr

            ind += 1

        hash_input = str(self.issuer_pk.g_snake) + str(com) + \
            str(self.issuer_pk.Y_snake_list) + str(message)

        proof = int(hashlib.sha256(hash_input.encode('utf-8')
                                   ).hexdigest(), 16)

        # print(f'proof client side: {proof}')

        return (sigma_prime, self.disclosed_attributes, proof)
