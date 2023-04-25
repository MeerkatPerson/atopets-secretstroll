
from math import sqrt

from typing import Tuple, List, Dict

import timeit

from keys import PublicKey, SecretKey

from credential import generate_key

from user import User

from service_provider import ServiceProvider

import statistics

from petrelic.multiplicative.pairing import G1, G2, G1Element

import random

import string

# import pandas as pd

# import seaborn as sns

# import matplotlib.pyplot as plt

# ---------------------------------------------------
# Type aliases

AttributeMap = Dict[str, int]

IssueRequest = Tuple[int, List[int], G1Element, str]

Signature = Tuple[G1Element, G1Element]

BlindSignature = Tuple[Signature, AttributeMap]

AnonymousCredential = Tuple[Signature, AttributeMap]

DisclosureProof = Tuple[Signature, AttributeMap, int]

# ---------------------------------------------------------------------------------------------------
# Measure computing cost (= time) for key generation
# Check if/how computing cost depends on number of attributes


def benchmark_keygen() -> Dict[str, Tuple[int, int]]:

    # QUESTION: should compute how computation cost depends on length of attribute list?

    key_gen_measurements = []

    times_arr = []

    # Test for a number of available subscriptions of up to 20 (more is unrealistic)
    for i in range(1, 21):

        available_subscriptions: List[str] = []

        username: str = 'zoé'

        # Generate i available subscriptions
        for j in range(i):

            elem = ''.join(random.choices(string.ascii_uppercase +
                                          string.digits, k=7))

            available_subscriptions.append(elem)

        attributes: List[str] = available_subscriptions + [username]

        # raw_times = []

        for k in range(100):

            # Start timer
            starttime = timeit.default_timer()

            # Generate keypair
            res: Tuple[SecretKey, PublicKey] = generate_key(attributes)

            # Compute time taken
            time_taken = timeit.default_timer() - starttime

            # Append to measurements array
            times_arr.append(time_taken)

            # Append to dict for plotting
            key_gen_measurements.append(
                {'attr_len': i, 'run': k, 'time_taken': time_taken})

    # Print overall mean and SE
    print(
        f'[Key Generation] Mean over 1-20 available subscriptions with 100 runs each: {statistics.mean(times_arr)}, SE: {statistics.stdev(times_arr)/sqrt(20*100)}')

    # return dictionary with measurements
    return key_gen_measurements

# ---------------------------------------------------------------------------------------------------
# Measure computing cost (= time) for issuance
# Check if/how computing cost depends on number of attributes


def benchmark_issuance() -> Dict[str, Tuple[int, int]]:

    username: str = 'zoé'

    issuance_measurements = []

    times_arr = []

    # Test for a number of available subscriptions of up to 20 (more is unrealistic)
    for i in range(1, 21):

        available_subscriptions = []

        # Generate i available subscriptions
        for j in range(i):

            elem = ''.join(random.choices(string.ascii_uppercase +
                                          string.digits, k=7))

            available_subscriptions.append(elem)

        attributes: List[str] = available_subscriptions + [username]

        # Generate a key pair for the issuer
        provider_pk, provider_sk = generate_key(attributes)

        # create a user (let them choose all available subscriptions)
        chosen_subscriptions = attributes

        user = User(provider_pk, chosen_subscriptions, 'zoé')

        # create a service provider
        provider = ServiceProvider(
            provider_pk, provider_sk, chosen_subscriptions, username)

        # -------------------------------------------------------------------------------------------

        # raw_times = []

        for k in range(100):

            # Start timer
            starttime = timeit.default_timer()

            # create an issue request
            issue_request = user.create_issue_request()

            # sign the issuance request
            res = provider.sign_issue_request(issue_request)

            # Next, the user must unblind the signature
            credential = user.obtain_credential(res)

            # Compute time taken
            time_taken = timeit.default_timer() - starttime

            # Append to measurements array
            times_arr.append(time_taken)

            # Append to dict for plotting
            issuance_measurements.append(
                {'attr_len': i, 'run': k, 'time_taken': time_taken})

     # Print overall mean and SE
    print(
        f'[Issuance Generation] Mean over 1-20 available subscriptions with 100 runs each: {statistics.mean(times_arr)}, SE: {statistics.stdev(times_arr)/sqrt(20*100)}')

    # return dictionary with measurements
    return issuance_measurements

# ---------------------------------------------------------------------------------------------------
# Measure computing cost (= time) for showing & verification
# Check if/how computing cost depends on number of attributes


def benchmark_verification() -> Tuple[Dict[str, Tuple[int, int]], Dict[str, Tuple[int, int]]]:

    username: str = 'zoé'

    showing_measurements = []
    times_arr_showing = []

    verification_measurements = []
    times_arr_verification = []

    # Test for a number of available subscriptions of up to 20 (more is unrealistic)
    for i in range(1, 21):

        available_subscriptions = []

        # Generate i available subscriptions
        for j in range(i):

            elem = ''.join(random.choices(string.ascii_uppercase +
                                          string.digits, k=7))

            available_subscriptions.append(elem)

        attributes: List[str] = available_subscriptions + [username]

        # Generate a key pair for the issuer
        provider_pk, provider_sk = generate_key(attributes)

        # create a user (let them choose all available subscriptions)
        chosen_subscriptions = attributes

        user = User(provider_pk, chosen_subscriptions, 'zoé')

        # create a service provider
        provider = ServiceProvider(
            provider_pk, provider_sk, chosen_subscriptions, username)

        # create an issue request
        issue_request = user.create_issue_request()

        # sign the issuance request
        res = provider.sign_issue_request(issue_request)

        # Next, the user must unblind the signature
        credential = user.obtain_credential(res)

        # -------------------------------------------------------------------------------------------

        for k in range(100):

            # ---------------------------------------------------------
            # Measure showing

            # Start timer
            starttime = timeit.default_timer()

            message: bytes = (f"{46.52345},{6.57890}").encode("utf-8")

            disclosure_proof: DisclosureProof = user.create_disclosure_proof(
                credential, message)

            # Compute time taken
            time_taken_showing = timeit.default_timer() - starttime

            # Append to measurements array
            times_arr_showing.append(time_taken_showing)

            showing_measurements.append(
                {'attr_len': i, 'run': k, 'time_taken': time_taken_showing})

            # ---------------------------------------------------------
            # Measure verification

            # Start timer
            starttime = timeit.default_timer()

            disclosure_res: bool = provider.verify_disclosure_proof(
                disclosure_proof, message)

            # Compute time taken
            time_taken_verify = timeit.default_timer() - starttime

            # Append to measurements array
            times_arr_verification.append(time_taken_verify)

            verification_measurements.append(
                {'attr_len': i, 'run': k, 'time_taken': time_taken_verify})

    # Print overall mean and SE
    print(
        f'[Showing] Mean over 1-20 available subscriptions with 100 runs each: {statistics.mean(times_arr_showing)}, SE: {statistics.stdev(times_arr_showing)/sqrt(20*100)}')

    # Print overall mean and SE
    print(
        f'[Verification] Mean over 1-20 available subscriptions with 100 runs each: {statistics.mean(times_arr_verification)}, SE: {statistics.stdev(times_arr_verification)/sqrt(20*100)}')

    # Compute mean and SE
    return showing_measurements, verification_measurements


if __name__ == "__main__":

    benchmark_keygen = benchmark_keygen()

    benchmark_issuance = benchmark_issuance()

    benchmark_showing, benchmark_verification = benchmark_verification()

    '''
    UNCOMMENT TO GENERATE PLOTS (REQUIRES PANDAS & SEABORN)

    keygen_df = pd.DataFrame(benchmark_keygen)

    # Remove outliers (99 % percentile)
    low = 0.01
    high = 0.99
    keygen_df_quant = keygen_df.quantile([low,high])
    keygen_df = keygen_df.apply(lambda x: x[(x > keygen_df_quant.loc[low, x.name]) & (x < keygen_df_quant.loc[high, x.name])], axis=0)

    keygen_plot = sns.ecdfplot(data=keygen_df, hue='attr_len', x='time_taken', palette='RdBu')

    norm=plt.Normalize(keygen_df.attr_len.min(),keygen_df.attr_len.max())
    sm=plt.cm.ScalarMappable(cmap="RdBu",norm=norm)
    sm.set_array([])

    keygen_plot.get_legend().remove()
    keygen_plot.figure.colorbar(mappable=sm, label='Number of attributes')
    keygen_plot.set_title('Key generation duration')
    keygen_plot.set_xlabel('Time taken (ms)')
    keygen_plot.get_figure().savefig('keygen_plot.png')

    plt.close()

    issuance_df = pd.DataFrame(benchmark_issuance)

    # Remove outliers (99 % percentile)
    low = 0.01
    high = 0.99
    issuance_df_quant = issuance_df.quantile([low,high])
    issuance_df = issuance_df.apply(lambda x: x[(x > issuance_df_quant.loc[low, x.name]) & (x < issuance_df_quant.loc[high, x.name])], axis=0)

    issuance_plot = sns.ecdfplot(data=issuance_df, hue='attr_len', x='time_taken', palette='RdBu')
    issuance_plot.get_legend().remove()
    issuance_plot.figure.colorbar(mappable=sm, label='Number of attributes')
    issuance_plot.set_title('Issuance duration')
    issuance_plot.set_xlabel('Time taken (ms)')
    issuance_plot.get_figure().savefig('issuance_plot.png')

    plt.close()

    showing_df = pd.DataFrame(benchmark_showing)

    # Remove outliers (99 % percentile)
    low = 0.01
    high = 0.99
    showing_df_quant = showing_df.quantile([low,high])
    showing_df = showing_df.apply(lambda x: x[(x > showing_df_quant.loc[low, x.name]) & (x < showing_df_quant.loc[high, x.name])], axis=0)

    showing_plot = sns.ecdfplot(data=showing_df, hue='attr_len', x='time_taken', palette='RdBu')
    showing_plot.get_legend().remove()
    showing_plot.figure.colorbar(mappable=sm, label='Number of attributes')
    showing_plot.set_title('Showing duration')
    showing_plot.set_xlabel('Time taken (ms)')
    showing_plot.get_figure().savefig('showing_plot.png')

    plt.close()

    verification_df = pd.DataFrame(benchmark_verification)

    # Remove outliers (99 % percentile)
    low = 0.01
    high = 0.99
    verification_df_quant = verification_df.quantile([low,high])
    verification_df = verification_df.apply(lambda x: x[(x > verification_df_quant.loc[low, x.name]) & (x < verification_df_quant.loc[high, x.name])], axis=0)

    verification_plot = sns.ecdfplot(data=verification_df, hue='attr_len', x='time_taken', palette='RdBu')
    verification_plot.get_legend().remove()
    verification_plot.figure.colorbar(mappable=sm, label='Number of attributes')
    verification_plot.set_title('Verification duration')
    verification_plot.set_xlabel('Time taken (ms)')
    verification_plot.get_figure().savefig('verification_plot.png')

    plt.close()

    '''
