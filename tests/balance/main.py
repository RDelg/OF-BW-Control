from algorithm import rate_control

def main():
	max_bandwidth = 100
	requested = {
				'1':10,
				'2':20,
				'3':30,
				'4':10,
				'5':20,
				'6':10,
				'7':30
				}
	used = {
			'1':10,
			'2':18,
			'3':16,
			'4':6,
			'5':17,
			'6':9,
			'7':24
			}
	total_requested = sum(requested.values())
	total_used = sum(used.values())
	allocated, requested_mod = rate_control(max_bandwidth, requested, used)
	print 'Max bandwidth: %d Total requested: %d Total used: %d ' % (max_bandwidth, total_requested, total_used)
	print 'Total requested mod: %d' % sum(requested_mod.values())
	leftOver = max_bandwidth - sum(allocated.values())
	print 'leftOver: %d' % leftOver
	for src in sorted(allocated):
		print 'src: %s requested: %d used: %d  requested mod: %d allocated: %d' % (src, requested[src], used.get(src, -1), requested_mod[src], allocated[src])

if __name__ == "__main__":
	main()