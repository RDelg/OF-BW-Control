import requests
from time import time,sleep

def main():
	output = open('system.csv', 'w')

	while True:
		r = requests.get('http://192.168.56.102:8080/bandwidth/0000000000000002')
		j = r.json()
		a1 = j['Allocated']['4'].get('00:00:00:00:00:01', 0)
		a2 = j['Allocated']['4'].get('00:00:00:00:00:02', 0)
		a3 = j['Allocated']['4'].get('00:00:00:00:00:03', 0)
		u1 = j['Used']['4'].get('00:00:00:00:00:01', 0)
		u2 = j['Used']['4'].get('00:00:00:00:00:02', 0)
		u3 = j['Used']['4'].get('00:00:00:00:00:03', 0)
		output.write('%d, %d, %d, %d, %d, %d, %d \n' % (time(), a1, a2, a3, u1, u2, u3) )
		sleep(2)


if __name__ == '__main__':
	main()
