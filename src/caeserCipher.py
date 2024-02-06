from src.utils.utils import loadStatistics
from src.utils.stats import calculateLanguageCertainty
from collections import defaultdict

LETTERORDER = "abcdefghijklmnopqrstuvwxyz"
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25}

def decryptCaesar(ciphertext, spacesRemoved=False):

    minLoss = float('inf')
    minI = -1
    statsJson = loadStatistics(spacesRemoved)

    for i in range(1, 26):
        newPlaintext = ""
        for letter in ciphertext:
            if letter == " ":
                newPlaintext += " "
            else:
                newLetter = LETTERINDEX[letter] - i
                newLetter = newLetter % 26
                newPlaintext += LETTERORDER[newLetter]

        newLoss = calculateLanguageCertainty(newPlaintext, statsJson)

        if newLoss < minLoss:
            minLoss = newLoss
            minI = i

    return minI