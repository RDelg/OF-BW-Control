def rate_control(bandwith, requested, used):
	allocated = {}
	totalRequested = sum(requested.values())
	totalUsed = sum(used.values())
	partOfWhole = 0
	leftOver = 0
	if totalRequested < bandwith:
		allocated = requested
		leftOver = bandwith - totalRequested
	else:
		requested = requested.copy()
		for src in requested:
			tmp = int((used.get(src, requested[src]*0.5)*1.5))
			if tmp < requested[src]:
				requested[src] = tmp
			if requested[src] == 0:
				requested[src] = 5
		partOfWhole = int(bandwith/len(requested))
		leftOver = bandwith % len(requested)
		for src in requested:
			if partOfWhole > requested[src]:
				allocated[src] = requested[src]
				leftOver += partOfWhole - requested[src]
			else:
				allocated[src] = partOfWhole
		while leftOver > 0:
			stillNeed = 0
			for src in requested:
				if (requested[src] - allocated[src]) > 0:
					stillNeed += 1
			if stillNeed < leftOver:
				for src in requested:
					if (requested[src] - allocated[src]) > 0:
						 allocated[src]+=1
						 leftOver-=1
			else:
				maxDiff = 0
				for src in requested:
					if requested[src] - allocated[src] > maxDiff:
						maxDiff = requested[src] - allocated[src]
						tempI = src
				allocated[tempI] += 1
				leftOver -= 1
	return allocated
