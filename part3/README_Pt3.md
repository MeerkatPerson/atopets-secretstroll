# README Pt. 3: Tor Grid Cell Fingerprinting Attack

## Setup

For this part, we are assuming the same setup as in part 1. 

Importantly, we further assume that the `client` has already registered and obtained an anonymous credential and is ready to make queries.

Also, we assume that `tshark` is available in the `client` container. Note that this may require adapting the `docker-compose.yaml` to give more permissions to the `client`-container:

```
client:
    ...
    cap_add:
      - ALL
```

## Collecting data

With the `server` running in another process, execute the following command in the `client` container:

```
python3 experiment.py
```

This will collect `pcap` files in a directory called `capture`, compute statistics on those files, and save the results in a file called `results.json`.

Our data can be found in the `results` directory. The "raw" data files are the `.json` ones.

## Processing the data

Install all the packages in `requirements_classification.txt` for processing the data and training the classifier.

The notebook `fingerprinting_experiments.ipynb` transforms the data contained in the `.json`-files containing meta-information for the individual queries into a pandas df and writes it to `.pckl`. Note that the notebook currently uses precisely the `.json`-files that are contained in the `results`-directory. If you would like to use other ones, change the first lines of the notebook accordingly.

## Training the classifier

As mentioned in the previous section, the packages from `requirements_classification.txt` are required.

In `fingerprinting_experiments.ipynb`, the dataframe contained in the `results`-directory is read from pickle and a random forest classifier is trained on it using 10-fold cross validation. Metrics are collected and a plot showing feature importance is produced.
