from src.utils.utils import loadStatistics
from collections import defaultdict

LETTERORDER = "abcdefghijklmnopqrstuvwxyz"
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25}

def calculateLanguageCertainty(proposedPlaintext, spacesRemoved=False):

    statsJson = loadStatistics(spacesRemoved)
    counts = defaultdict(lambda: 0)


    for i in range(len(proposedPlaintext)):

        if proposedPlaintext[i] != " ":
            counts[proposedPlaintext[i]] += 1

        if i > 0:
            counts[proposedPlaintext[i-1:i+1]] += 1

        if i > 1:
            counts[proposedPlaintext[i-2:i+1]] += 1

    loss = 0
    for ngram, count in counts.items():
        try:
            # Using a naive loss function of distance between expected occurances as a percentage of expected value
            expected = statsJson[ngram] * (len(proposedPlaintext) - len(ngram))
            loss += abs(((count - expected))/expected)

        # KeyError will happen in the case that a bigram/trigram is not represented at all in the statistics json (probability of 0)
        # If we fully trusted our statistics this should return infinite loss, not 0
        except KeyError:
            loss += 0

    return loss

def decryptCaesar(ciphertext):

    minChi = float('inf')
    minI = -1

    for i in range(1, 26):
        newPlaintext = ""
        for letter in ciphertext:
            if letter == " ":
                newPlaintext += " "
            else:
                newLetter = LETTERINDEX[letter] - i
                newLetter = newLetter % 26
                newPlaintext += LETTERORDER[newLetter]

        newChi = calculateLanguageCertainty(newPlaintext)

        if newChi < minChi:
            minChi = newChi
            minI = i

    return minI
