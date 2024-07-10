import os
import random
import json

# Select random plaintext string from random .txt file in /txt/ directory (Add default path as sourceDir)
def selectPlainText(numWords, sourceDir="../cryptograph-gutenberg-corpus/data/text/"):

    fileList = os.listdir(sourceDir)
    chosenFile = ""
    fileFound = False
    while not fileFound:

        while not chosenFile.endswith(".txt"):
            chosenFile = fileList[random.randint(0, len(fileList)-1)]

        with open(sourceDir + chosenFile, "r", encoding="UTF-8") as file:
            text = file.read()

        wordList = text.split()

        if len(wordList) > numWords:
            fileFound = True
        else:
            chosenFile = ""

    wordStartIndex = random.randint(0, len(wordList)-(1+numWords))
    return " ".join(wordList[wordStartIndex:wordStartIndex+(numWords)]).strip()

# Load statistics json from the previous repo
def loadStatistics(spacesRemoved, sourceDir="../cryptograph-gutenberg-corpus/data/ngram/"):

    if spacesRemoved:
        filePath = sourceDir + "spaceless/aggregate_ngram_probabilities.json"
    else:
        filePath = sourceDir + "spaced/aggregate_ngram_probabilities.json"
    with open(filePath, "r") as file:
        ngramProbabilities = json.load(file)

    return ngramProbabilities

if __name__ == "__main__":
    sampleNum = 100
    plaintextSamples = []
    for i in range(sampleNum):
        plaintextSamples.append(selectPlainText(50))

    print(plaintextSamples)
    # Serializing json
    json_object = json.dumps(plaintextSamples, indent=4)

    # Writing to sample.json
    with open("samplePlaintext.json", "w") as outfile:
        outfile.write(json_object)