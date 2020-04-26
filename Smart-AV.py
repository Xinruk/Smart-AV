#!/usr/bin/python

from binary_studio import *
from sklearn.feature_extraction import FeatureHasher
import argparse
import os


def train_detector(benign_path, malicious_path, hasher):
    """Train the detector on the specified training data."""
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory, path))
        return targets
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
    cv_evaluate(X, y, hasher)
else:
    parser.print_help()
