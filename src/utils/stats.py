from collections import defaultdict


def __chiTest(expected, real):
    return abs((real-expected)/expected)

def __chiSquaredTest(expected, real):
    return pow((real-expected), 2)/expected

# TODO: Add optimization that exits the calculation early if it surpasses minChi
def calculateLanguageCertainty(proposedPlaintext, statsJson, curMin=float("inf")):

    counts = defaultdict(lambda: 0)

    for i in range(len(proposedPlaintext)):

        if proposedPlaintext[i] != " ":
            counts[proposedPlaintext[i]] += 1

        if i > 0:
            counts[proposedPlaintext[i-1:i+1]] += 1

        if i > 1:
            counts[proposedPlaintext[i-2:i+1]] += 1

    loss = 0
    for ngram, freq in statsJson.items():
        try:
            if len(ngram) < 3:
                # Using a naive loss function of distance between expected occurances as a percentage of expected value
                expected = freq * (len(proposedPlaintext) - len(ngram))
                loss += __chiSquaredTest(expected, counts[ngram])
                #loss += abs(((count - expected))/expected)


        # KeyError will happen in the case that a bigram/trigram is not represented at all in the statistics json (probability of 0)
        # If we fully trusted our statistics this should return infinite loss, not 0
        except ZeroDivisionError:
            loss += pow(counts[ngram], 2)
        
        #if curMin < loss:
        #    return loss

    return loss
