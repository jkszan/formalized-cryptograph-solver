from utils.utils import selectPlainText
from encryption.monoalphabeticCipher import MonoalphabeticCipher
from utils.stats import calculateLanguageCertainty

from collections import defaultdict

def getLetterStats(crypt):
    lettercounts = defaultdict(lambda: 0)
    for letter in crypt:
        if letter != " ":
            lettercounts[letter] += 1

    length = len(crypt)
    letterstats = {}
    for letter, count in lettercounts.items():
        letterstats[letter] = round(count/length, 4)

    return letterstats


def attemptDecrypt(cleancrypt, codex):
    decrypted = ""
    for letter in cleancrypt:
        if letter in codex.keys():
            decrypted += codex[letter]
        else:
            decrypted += letter
    return decrypted

T = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
T = T.lower()
import random
from utils.utils import loadStatistics
# Tries 1 million decryption keys and returns the best
def findMostLikely(cleanCrypt, T):

    statsJson = loadStatistics(False)


    letterstats = getLetterStats(cleanCrypt)
    most_common_letters = list(letterstats.items())
    most_common_letters.sort(key=lambda x: -x[1])

    most_common = []
    for key, _ in most_common_letters:
        most_common.append(key)

    for letter in T:
        if not letter.lower() in most_common:
            most_common.append(letter.lower())

    starting_codex = {}
    key = most_common

    for i, letter in enumerate(key):
        starting_codex[letter] = T[i]
    
    decrypted = attemptDecrypt(cleanCrypt, starting_codex)
    prox = calculateLanguageCertainty(decrypted, statsJson)

    curMin = prox
    maxCodex = starting_codex

    curProx = prox
    curKey = key.copy()

    for _ in range(1000000):
        codex = {}
        i = random.randint(0, len(curKey)-1)
        j = random.randint(0, len(curKey)-1)

        if i == j:
            if i == len(key)-1:
                j = j-1
            else:
                j = j+1
        swap = [i, j]
        
        newKey = curKey.copy()
        newKey[swap[0]], newKey[swap[1]] = curKey[swap[1]], curKey[swap[0]]

        for i, letter in enumerate(newKey):
            codex[letter] = T[i]
        
        decrypted = attemptDecrypt(cleanCrypt, codex)
        prox = calculateLanguageCertainty(decrypted, statsJson) #curMin)

        if prox < curMin:
            curMin = prox
            maxCodex = codex.copy()
            curKey = newKey
            a = 1
            b = 1
        
        # Random modification with slight possibility to take a worse option for next generation
        if prox < curProx or random.random() < 0.05:
            curProx = prox
            curKey = newKey

    print(maxCodex)
    print(curMin)
    print(attemptDecrypt(cleanCrypt, maxCodex))
    return(maxCodex)

cleanCrypt = selectPlainText(50)
cipher = MonoalphabeticCipher()
cleanCrypted = cipher.encrypt(cleanCrypt)
print(cleanCrypt, "\n",cleanCrypted, T)
#cleanCrypt = removeSpaces(crypt2c)

codex = findMostLikely(cleanCrypted, T)
print(codex)
lettersAccurate, percentAccurate = cipher.evalProposedKey(cleanCrypted, codex)
print("LettersAc:", lettersAccurate, "PercentAc:", percentAccurate)
print(cipher.keyCodex)

