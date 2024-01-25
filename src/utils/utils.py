import os
import random
import json

# Select random plaintext string from random .txt file in /txt/ directory (Add default path as sourceDir)
def selectPlainText(numWords, sourceDir="../cryptograph-gutenberg-corpus/data/text/"):
    # return plainText
    fileList = os.listdir(sourceDir)
    chosenFile = ""
    while not chosenFile.endswith(".txt"):
        chosenFile = fileList[random.randint(0, len(fileList)-1)]

    with open(sourceDir + chosenFile, "r", encoding="UTF-8") as file:
        text = file.read()

    wordList = text.split()
    wordStartIndex = random.randint(0, len(wordList)-(1+numWords))
    return " ".join(wordList[wordStartIndex-1:wordStartIndex+(1+numWords)])

# Load statistics json from the previous repo
def loadStatistics(spacesRemoved, sourceDir="../cryptograph-gutenberg-corpus/data/ngram/"):

    if spacesRemoved:
        filePath = sourceDir + "spaceless/aggregate_ngram_probabilities.json"
    else:
        filePath = sourceDir + "spaced/aggregate_ngram_probabilities.json"
    with open(filePath, "r") as file:
        ngramProbabilities = json.load(file)

    return ngramProbabilities
