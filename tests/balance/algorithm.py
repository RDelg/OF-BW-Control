def rate_control(bandwith, requested, used):
    allocated = {}
    totalRequested = sum(requested.values())
    totalUsed = sum(used.values())
    partOfWhole = 0
    leftOver = 0
    minRate = 2
    K_f = 1.5
    R_f = 0.5
    requestedMod = requested.copy()
    if totalRequested < bandwith:
        allocated = requested.copy()
        leftOver = bandwith - totalRequested
    else:
        defaultRate = []
        for src in requested:
            tmp = int((used.get(src, requested[src]*R_f/K_f)*K_f))
            if tmp < requested[src]:
                requestedMod[src] = tmp
            if requestedMod[src] < minRate:
                requestedMod[src] = minRate
                defaultRate.append(src)
        totalRequested = sum(requestedMod.values())
        if totalRequested < bandwith:
            allocated = requestedMod
            leftOver = bandwith - totalRequested
        else:
            partOfWhole = int(bandwith/len(requestedMod))
            leftOver = bandwith % len(requestedMod)
            for src in requestedMod:
                if partOfWhole > requestedMod[src]:
                    allocated[src] = requestedMod[src]
                    leftOver += partOfWhole - requestedMod[src]
                else:
                    allocated[src] = partOfWhole
            while leftOver > 0 and len(defaultRate) != len(allocated):
                stillNeed = 0
                for src in requestedMod:
                    if (requested[src] - allocated[src]) > 0:
                        stillNeed += 1
                if stillNeed < leftOver:
                    for src in requestedMod:
                        if requested[src] - allocated[src] > 0 and src not in defaultRate:
                             allocated[src]+=1
                             leftOver-=1
                else:
                    maxDiff = 0
                    tempI = ''
                    for src in requested:
                        if requested[src] - allocated[src] > maxDiff and src not in defaultRate:
                            maxDiff = requested[src] - allocated[src]
                            tempI = src
                    allocated[tempI] += 1
                    leftOver -= 1
    return allocated, requestedMod