#!/usr/bin/python

from binary_studio import *
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher
import argparse
import os
import pickle
import numpy


def get_training_paths(directory):
    """Return a list of all binaries in the given directory."""
    targets = []
    for path in os.listdir(directory):
        targets.append(os.path.join(directory, path))
    return targets


def train_detector(benign_path, malicious_path, hasher):
    """Train the detector on the specified training data."""
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    # X features
    X = [get_number_of_imports(path)
         for path in malicious_paths + benign_paths]
    # y Data ref
    y = [1 for i in range(len(malicious_paths))] + \
        [0 for i in range(len(benign_paths))]
    classifier = tree.RandomForestClassifier(64)
    classifier.fit(X, y)
    pickle.dump((classifier, hasher), open("saved_detector.pkl", "w+"))


def get_training_data(benign_path, malicious_path, hasher):
    """Return X features and y data ref on the specified training data."""
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    X = [get_number_of_imports(path) for path in
         malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + \
        [0 for i in range(len(benign_paths))]
    return X, y


def evaluate(X, y, hasher):
    """Perform a cross-validation to evaluate our model."""
    import random
    from sklearn import metrics
    from matplotlib import pyplot
    from sklearn.cross_validation import KFold
    X, y = numpy.array(X), numpy.array(y)
    fold_counter = 0
    for train, test in KFold(len(X), 2, shuffle=True):
        training_X, training_y = X[train], y[train]
        test_X, test_y = X[test], y[test]
        classifier = RandomForestClassifier(64)
        classifier.fit(training_X, training_y)
        scores = classifier.predict_proba(test_X)[:, -1]
        fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
        pyplot.semilogx(fpr, tpr, label="ROC curve".format(fold_counter))
        fold_counter += 1
        break
    pyplot.xlabel("detector false positive rate")
    pyplot.ylabel("detector true positive rate")
    pyplot.title("Detector ROC curve")
    pyplot.legend()
    pyplot.grid()
    pyplot.show()


parser = argparse.ArgumentParser()
parser.add_argument("--malware_paths", default=None,
                    help="Path to malware files for training")
parser.add_argument("--benignware_paths", default=None,
                    help="Path to benignware files for training")
parser.add_argument("--evaluate", default=False,
                    action="store_true", help="Perform cross-validation")

args = parser.parse_args()

# Change hasher for a better understanding
hasher = FeatureHasher(20000)
if args.malware_paths and args.benignware_paths and not args.evaluate:
    train_detector(args.benignware_paths, args.malware_paths, hasher)
elif args.malware_paths and args.benignware_paths and args.evaluate:
    X, y = get_training_data(
        args.benignware_paths, args.malware_paths, hasher)
    evaluate(X, y, hasher)
else:
    parser.print_help()
