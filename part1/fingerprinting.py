import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pandas as pd
import sys
import statistics

def classify(train_features, train_labels, test_features, test_labels):
    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html

    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)

    # Compute performance metrics
    confusion_matrix_ = confusion_matrix(test_labels,predictions)
    classification_report_ = classification_report(test_labels,predictions)
    accuracy_score_ = accuracy_score(test_labels, predictions)

    # print(accuracy_score(test_labels, predictions))

    metrics = (confusion_matrix_, classification_report_, accuracy_score_)

    return predictions, metrics

def find_percentage_agreement(s1, s2):
    assert len(s1)==len(s2), "Lists must have the same shape"
    nb_agreements = 0  # initialize counter to 0
    for idx, value in enumerate(s1):
        if s2[idx] == value:
            nb_agreements += 1

    percentage_agreement = nb_agreements/len(s1)

    return percentage_agreement


def perform_crossval(features, labels, folds=10):
    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.

    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)
    accuracies = []

    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions, metrics = classify(X_train, y_train, X_test, y_test)
        # TODO do sth with metrics
        accuracy = find_percentage_agreement(predictions.tolist(), y_test.tolist())
        print(accuracy)
        accuracies.append(accuracy)

    print(f'Mean accuracy: {statistics.mean(accuracies)}')

    ###############################################
    # TODO: Write code to evaluate the performance of your classifier
    ###############################################


def load_data():
    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace

    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  

    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    ###############################################
    # TODO: Complete this function.
    ###############################################

    df = pd.read_pickle('./data_2604.pkl')

    labels_only_df = df['cell']

    features_only_df = df.drop('cell', axis = 1)

    features = features_only_df.values.tolist()
    labels = labels_only_df.values.tolist()

    return features, labels


def main():
    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    perform_crossval(features, labels, folds=10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
