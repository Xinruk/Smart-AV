#!/usr/bin/python3

import pefile
from sklearn.feature_extraction import FeatureHasher
import re
import numpy

def get_number_of_imports(path):
    """For a given binary this fonction return the number of import."""
    try:
        pe = pefile.PE(path)
        dei = pe.DIRECTORY_ENTRY_IMPORT
    except AttributeError as AttriError:
        # print("%s : %s" % (path, AttriError))
        pass
    except PEFormatError as formatError:
        # print("%s : %s" % (path, formatError))    
        pass

    finally:
        return 0

    nb_of_import = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for function in entry.imports:
            if function.name:
                nb_of_import += 1
    return nb_of_import

def get_string_features(path,hasher):
    # extract strings from binary file using regular expressions
    chars = r" -~"
    min_length = 5
    string_regexp = '[%s]{%d,}' % (chars, min_length)
    file_object = open(path)
    data = file_object.read()
    pattern = re.compile(string_regexp)
    strings = pattern.findall(data)

    # store string features in dictionary form
    string_features = {}
    for string in strings:
        string_features[string] = 1

    # hash the features using the hashing trick
    hashed_features = hasher.transform([string_features])

    # do some data munging to get the feature array
    hashed_features = hashed_features.todense()
    hashed_features = numpy.asarray(hashed_features)
    hashed_features = hashed_features[0]

    # return hashed string features
    # print("Extracted {0} strings from {1}").format(len(string_features), path)
    return hashed_features

def is_binary_is_packed(path):
    """For a given binary this fonction detrmine if it's packed or not.

        To check this out, we will check on 5 points:
        - Check the Magic Number
        - Number of Standard and Non Standard Sections
        - File Entropy
        - Number executable section
        - 
    """

    pe = pefile.PE(path)
    print("Magic Number : " + hex(pe.DOS_HEADER.e_magic))
    print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))


def get_amount_of_encrypted_data(path):
    """For a given binary this function return the % of unclear data."""
    pass
