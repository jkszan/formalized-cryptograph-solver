import sys,os
sys.path.append(os.getcwd())

from decimal import Decimal as D
from src.utils.utils import loadStatistics, selectPlainText
from src.encryption.monoalphabeticCipher import MonoalphabeticCipher
from collections import defaultdict

LETTERORDER = "abcdefghijklmnopqrstuvwxyz "
LETTERINDEX = {'a': 0, 'b': 1, 'c': 2, 'd': 3,
               'e': 4, 'f': 5, 'g': 6, 'h': 7,
               'i': 8, 'j': 9, 'k': 10, 'l': 11,
               'm': 12, 'n': 13, 'o': 14, 'p': 15,
               'q': 16, 'r': 17, 's': 18, 't': 19,
               'u': 20, 'v': 21, 'w': 22, 'x': 23,
               'y': 24, 'z': 25, ' ': 26}
MOSTCOMMONORDER = "etaoinshrdlcumwfgypbvkjxqz"


class DistributionMatrix:


    # X | A  | B | C | D | E | ... | " " |
    # A | AA | AB| AC| AD| AE
    # B | BA | BB| BC| BD| BE
    # Where 
    # rowMap gives ciphertext to plaintext mappings
    


    # TODO: Have frequencies put in (For the E matrix we need to precalc stats[first + second] * (ciphertextLength-1))
    # TODO: For spaced variants we need to change how expected distribution 
    def __init__(self, initialLetterKey, frequencies):
        """
            Constructor for DistributionMatrix, first initializes the rowMap to the initial key sequence then populates the letterMatrix
            with expected bigram frequencies
        """
        # The bigram frequency matrix of the punative plaintext
        
        
        # Rowmap maps from index to Plaintext
        self.rowMap : dict[int, str] = {}
        self.letterMatrix : list[list[int]] = [[0]*len(LETTERORDER) for _ in range(len(LETTERORDER))] # Square [0][0] corresponds to ciphertext bigram AA, and plaintext bigram rowMap[0] + colMap[0]


        print(initialLetterKey)
        for ciphertextLetter, plaintextLetter in initialLetterKey.items():
            self.rowMap[LETTERINDEX[ciphertextLetter]] = plaintextLetter
        
        self.rowMap[LETTERINDEX[" "]] = " "

        print(self.rowMap)
        for rowIndex in range(len(LETTERORDER)):
            for colIndex in range(len(LETTERORDER)):
                firstLetter = self.rowMap[rowIndex]
                secondLetter = self.rowMap[colIndex]
                # real [a][b] = 12
                # fake [a:a][b:k] := 12
                # 1 -> b -> b:k -> k
                self.letterMatrix[rowIndex][colIndex] = frequencies[LETTERORDER[rowIndex] + LETTERORDER[colIndex]]

                if LETTERORDER[rowIndex] + LETTERORDER[colIndex] == "ab":
                    print(rowIndex, colIndex)
                    print(LETTERORDER[rowIndex] + LETTERORDER[colIndex], frequencies[LETTERORDER[rowIndex]+LETTERORDER[colIndex]])
    
    def cipherTextToIndex(self, ciphertextLetter):
        return LETTERINDEX[ciphertextLetter]


    def get(self, firstIndex, secondIndex):
        """
        Helper function to get the bigram frequency of a plaintext bigram from two ciphertext indexes
        """
        return self.letterMatrix[firstIndex][secondIndex]
    
    def swapRowAndColumns(self, rowOne, rowTwo):

        # Swap rows and columns
        self.swapRows(rowOne, rowTwo)
        self.swapColumns(rowOne, rowTwo)
        self.rowMap[rowOne], self.rowMap[rowTwo] = self.rowMap[rowTwo], self.rowMap[rowOne]

    def swapRows(self, rowOne, rowTwo):
        self.letterMatrix[rowOne], self.letterMatrix[rowTwo] = self.letterMatrix[rowTwo], self.letterMatrix[rowOne]

    def swapColumns(self, colOne, colTwo):
    
        for i in range(len(self.letterMatrix)):
            self.letterMatrix[i][colOne], self.letterMatrix[i][colTwo] = self.letterMatrix[i][colTwo], self.letterMatrix[i][colOne]

    def calculateScoreOnRowColumn(self, expectationMatrix, rowOne, rowTwo):

        scoreDelta = 0
        for i in range(len(LETTERORDER)):
            scoreDelta += abs(self.letterMatrix[rowOne][i] - expectationMatrix.letterMatrix[rowOne][i])
            scoreDelta += abs(self.letterMatrix[rowTwo][i] - expectationMatrix.letterMatrix[rowTwo][i])

        for i in range(len(LETTERORDER)):    
            if i != rowOne and i != rowTwo:
                scoreDelta += abs(self.letterMatrix[i][rowOne] - expectationMatrix.letterMatrix[i][rowOne])
                scoreDelta += abs(self.letterMatrix[i][rowTwo] - expectationMatrix.letterMatrix[i][rowTwo])

        return scoreDelta
    
    def calculateFullScore(self, expectationMatrix):

        score = 0
        for row in range(len(self.letterMatrix)):
            for col in range(len(self.letterMatrix[row])):
                #score += pow(self.letterMatrix[row][col] - expectationMatrix.letterMatrix[row][col], 2)
                score += abs(self.letterMatrix[row][col] - expectationMatrix.letterMatrix[row][col])
        return score

def swapElements(key, i, j):
    swp = key[i]
    key[i] = key[j]
    key[j] = swp
    #key[i], key[j] = key[j], key[i]
    return key

# Initialize the key maybe randomly, probably have most common unigram = most common ciphertext
def getCheaterMatrix(digramCounts, spaceStartDigramCount, spaceEndDigramCount, digramCount, spacesRemoved=False):
    letterKey = {}
        
    # Iterating through every digram possibility
    for first in LETTERORDER:
        letterKey[first] = first

    # Creating a distribution matrix for our expected values
    return DistributionMatrix(letterKey, digramCounts)

# Initialize the key maybe randomly, probably have most common unigram = most common ciphertext
def initializeExpectationMatrix(spaceStartDigramCount, spaceEndDigramCount, digramCount, spacesRemoved=False):
    stats = loadStatistics(spacesRemoved=spacesRemoved)
    expectedFrequencies = {}
    letterKey = {}
        
    # Iterating through every digram possibility
    for first in LETTERORDER:
        letterKey[first] = first
        for second in LETTERORDER:

            # Setting our expected number of occurances of each bigram, if the bigram is not expected at all (key error) we set to 0
            try:
                expectedFrequencies[first+second] = stats[first + second]

                if first == " ":
                    expectedFrequencies[first+second] = expectedFrequencies[first+second]*spaceStartDigramCount
                elif second == " ":
                    expectedFrequencies[first+second] = expectedFrequencies[first+second]*spaceEndDigramCount
                else:
                    expectedFrequencies[first+second] = expectedFrequencies[first+second]*digramCount

            except KeyError:
                expectedFrequencies[first+second] = 0

    # Creating a distribution matrix for our expected values
    return DistributionMatrix(letterKey, expectedFrequencies)

def getDigramFreqSpaceful(punativePlaintext):
    digramCounts = defaultdict(lambda: 0)

    digramCount = 0
    spaceStartDigramCount = 0
    spaceEndDigramCount = 0

    for i in range(1, len(punativePlaintext)-1):
        digramCounts[punativePlaintext[i-1:i+1]] += 1
    
        if punativePlaintext[i] == " ":
            spaceStartDigramCount += 1
        elif punativePlaintext[i+1] == " ":
            spaceEndDigramCount += 1
        else:
            digramCount += 1
    
    digramFreq = defaultdict(lambda: 0)
    for digram, count in digramCounts.items():

        #print("t" + digram + "t")
        #print(digramCounts)
        if digram[0] == " ":
            digramFreq[digram] = count #/ spaceStartDigramCount
        elif digram[1] == " ":
            digramFreq[digram] = count #/ spaceEndDigramCount
        else:
            digramFreq[digram] = count #/ digramCount
        #digramFreq[digram] = count
    
    return digramFreq, spaceStartDigramCount, spaceEndDigramCount, digramCount

def generateInitialKey(ciphertext):

    letterCounts = {}

    for letter in LETTERORDER:

        if letter != " ":
            letterCounts[letter] = 0

    for letter in ciphertext:
        if letter != " ":
            letterCounts[letter] += 1
    
    letterOrder = list(letterCounts.items())
    letterOrder.sort(key=lambda x: -x[1])
    print(letterOrder)

    initialKey = {}

    for i in range(len(letterOrder)):
        nextLetter = letterOrder[i][0]
        initialKey[nextLetter] = MOSTCOMMONORDER[i]
    #print(letterOrder)
    #print(initialKey)
    return initialKey

def visualizeMatrix(colNames, rowNames, matrix):
    print('\t'.join(list(LETTERORDER)))
    print('\n'.join(['\t'.join([str(round(cell, 2)) for cell in row]) for row in matrix]))


# TODO: Fix so key is dictionary
def jakobsensFastAlgorithm(spacesRemoved = False):

    plaintext = selectPlainText(400)
    #plaintext = """have become to the environment yet we must naturally rebel against being spirited away from this glorious world of ours to perhaps be on jupiter much in the same manner as we have upon strange animals here for some time i have suspected that abaris in his grotesque way is exceptionally of allie she has for nothing her every wish has been but he will not consent to our before the multitude unless we submit to being under a strange power in other words we are forced to undergo hypnotism for a reason that i have not been able to learn that is why we did not see you when you stood before the platform in the throne chamber as allie told you there is one exit from this underground world and that is guarded constantly either by the jovians themselves or their grotesque death dealing mechanical guards in the shape of a cactus tree with arms like an octopus the mechanical jovians seem to have all the powers of the creatures themselves only their mental unless by a living hand they are helpless these jovians are really in all forms you have seen the series of spheres in the throne room with the large hall in the center the large sphere is jupiter in a miniature orbit the small spheres are its moons as good abaris to us through these they are able to watch the progress of their radium spheres as they shoot their way toward jupiter the large spheres show their passage very plainly but these explanations of jovian objects and scientific genius are not getting us to our goal so let us consider the possibility of escape i have a plan that we may be able to use i intently to the plan of possible action as lane outlined it to sands allies father that at a certain time the guards at the only avenue of escape would be and the mechanical jovians with their tentacle like arms by a remote central would be put in their places lane how he had previously the source of control over the mechanical men and was therefore perhaps in the position to disconnect the system and suspend their activity this like a very excellent plan but how i thought would it be possible for us to steal near the central control apparatus in our attempt to disconnect it surely the jovians must maintain a constant guard over such delicate and important apparatus but on the other hand they may not feel a need of it in view of the fact that allie lane and her father had been with them so long that they accepted them as being harmless at any rate sands of the plan and it was decided that the attempt to escape would be made at a time when lane was to give a low whistle and we would all meet in allies chamber providing of course that the way was clear lane with his forefinger drew an invisible outline showing the tunnel through which we were to go sands watched him closely and absorbed the information meanwhile i shot rapid glances around the chamber in its entirety in my part as guard several times my heart when i sounds that softly broke the stillness of the cavern but the sounds to bring what i the grotesque jovians sands was standing in the center of the room now allie lane in his arms they endearingly allies father paced the floor nervously suddenly lane stopped and faced his daughter and her lover he his lips to say something thought better of it then turned half away he swung around presently as though he had decided on some question him and spoke softly allie his words nervous and tense me you love bob dont you dear as well as life father she sands turned to look at lane puzzled suppose then lane returned that you marry bob now it would be a good thing in the face of whatever confronts us i would marry him now father allie said in a half whisper that i barely caught but how you forget my dear that i was a minister back in kansas city her father a long time allie sands put in holding allies shoulder and looking into her eyes lovingly then i will marry you at once robert she said her eyes shining with happy tears father can perform the ceremony fascinated i watched the procedure that forgetting my duty as guard in whose hands must rest the lives of the happy three with my eyes and attention on allie as she whispered i do i to notice that abaris had suddenly come to the entrance of the chamber and was standing there silently regarding the trio lane was saying i now pronounce you man and wife when i beheld abaris towering form as he stood menacingly just inside the room the tubes of his forehead stuck out rigidly his tentacle like arms in anger and his owlish eyes and closed rapidly i shrank back into the darkness of the tunnel fearful lest i be discovered from my place however i could see the entire chamber as though struck by some terrific force sands and lane at once spun around and faced abaris allie a fearful little cry and shrank back against the wall abaris tubes were pointed at them menacingly and i knew that he was speaking to them in his peculiar mental telepathy what words flew between them i was not able to catch for i had learned that i could not receive the wave vibrations unless the tubes were pointing directly at me suddenly i sands words as he angrily informed abaris that allie had just become his wife and that it was no mans business what he was doing in the chamber with her his features with growing anger as he spoke his hands were you frog face i him shout for allie lane"""
    print(plaintext)
    #plaintext = plaintext.replace(" ", "")
    cipher = MonoalphabeticCipher()
    ciphertext = cipher.encrypt(plaintext)

    punativeKey = generateInitialKey(ciphertext)
    #print(punativeKey)
    punativePlaintext = cipher.decrypt(ciphertext, punativeKey)
    
    if not spacesRemoved:
        digramFrequencies, spaceStartDigramCount, spaceEndDigramCount, digramCount = getDigramFreqSpaceful(punativePlaintext)

    digramDist = DistributionMatrix(punativeKey, digramFrequencies)
    expectedDist = initializeExpectationMatrix(spaceStartDigramCount, spaceEndDigramCount, digramCount, spacesRemoved=False)
    
    #print(punativeKey)
    #visualizeMatrix([], [], expectedDist.letterMatrix)
    #print("\nDONE\n")
    #visualizeMatrix([], [], digramDist.letterMatrix)
    #print("\nREAL\n")
    #visualizeMatrix([], [], cheater.letterMatrix)
    print("Initial", cipher.evalProposedKey(ciphertext, punativeKey))
    #print("Realkey", cipher.keyCodex)
    #print("StartingKey", punativeKey)

    #print(digramDist.rowMap)
    #print(expectedDist, digramDist)
    #print(expectedDist.letterMatrix == digramDist.letterMatrix)
    #print(expectedDist.rowMap == digramDist.rowMap)

    #lastIterScore = float('inf')
    #while lastIterScore > digramDist.score:
    #    lastIterScore = digramDist.score
    a = 1
    b = 1
    done = False
    while not done:
        #print(a, b)

        if a + b <= 26:
            curScore = digramDist.calculateFullScore(expectedDist)
            #curValue = digramDist.calculateScoreOnRowColumn(expectedDist, a-1, a+b-1)
            digramDist.swapRowAndColumns(a-1, a+b-1) # Step 7
            newScore = digramDist.calculateFullScore(expectedDist)
            #newValue = digramDist.calculateScoreOnRowColumn(expectedDist, a-1, a+b-1) # Step 8
            #print(curValue, newValue)
            #print(newValue - curValue)
            if newScore < curScore: # Step 9
                punativeKey = swapElements(punativeKey, LETTERORDER[a-1], LETTERORDER[a+b-1])
                a = 1
                b = 1
            else:
                #print(digramDist.calculateFullScore(expectedDist))
                digramDist.swapRowAndColumns(a-1, a+b-1)
                a = a + 1
                #print(digramDist.calculateFullScore(expectedDist), curScore)
                assert digramDist.calculateFullScore(expectedDist) == curScore
        else:
            a = 1
            b = b + 1

            if b == 26:
                done = True
        print(curScore, newScore, end='\r')

    punativePlaintext = cipher.decrypt(ciphertext, punativeKey)
    #print(plaintext, "\n")
    print(punativeKey)
    print("Final", cipher.evalProposedKey(ciphertext, punativeKey))
    print(cipher.keyCodex)
    print(punativeKey)
    #print(ciphertext)
    #print(plaintext)
    #print(punativePlaintext)
    print("FINALDIST")
    visualizeMatrix([], [], digramDist.letterMatrix)

    print("Correct Keys:")
    realKey = cipher.keyCodex
    for key, val in punativeKey.items():
        if realKey[key] == val:
            print(val, end = " ")
    
    print("\nReal Cipher:", cipher.keyCodex)
    print("Derived:", punativeKey)
    
    #print(curScore)
    #print("BEF", punativeKey)
    #digramDist.swapRowAndColumns(LETTERINDEX["h"], LETTERINDEX["z"])
    #print(digramDist.calculateFullScore(expectedDist))
    #print(digramDist.rowMap[LETTERINDEX["q"]], digramDist.rowMap[LETTERINDEX["i"]])
    #punativeKey = swapElements(punativeKey, LETTERORDER[LETTERINDEX["h"]], LETTERORDER[LETTERINDEX["z"]])

    #print(cipher.evalProposedKey(ciphertext, punativeKey))
    #print(digramDist.rowMap)
    #print("AFT", punativeKey)
    #visualizeMatrix([], [], digramDist.letterMatrix)


    return punativeKey, punativePlaintext


for i in range(1):
    punativeKey, punativePlaintext = jakobsensFastAlgorithm()
    #print(punativePlaintext, "\n", punativeKey)