#!/usr/bin/python

import pefile


def get_number_of_imports(path):
    """For a given binary this fonction return the number of import."""
    pe = pefile.PE(path)
    nb_of_import = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for function in entry.imports:
            if function.name:
                nb_of_import += 1
    return nb_of_import


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
