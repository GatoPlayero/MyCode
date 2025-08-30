import threading
import time

exitFlag = 0

class myThread (threading.Thread):
	def __init__(self, threadID, name, counter):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
	def run(self):
		print("Starting " + self.name)
		self.my_print_time(self.name, 5, self.counter)
		print("Exiting " + self.name)
	def my_print_time(self, threadName, counter, delay):
		while counter:
			if exitFlag:
				threadName.exit()
			print("Thread [{0}] Sleeping [{1}] Counter [{2}]".format(threadName, delay+1, counter))
			time.sleep(delay+1)
			print("%s: %s" % (threadName, time.ctime(time.time())))
			counter -= 1
	
threadsList = range(2)	# range returns a list of integers from zero to one less than the parameter
###
###?threadsList[0]
### 0
###?threadsList[1]
### 1
###?threadsList[2]
### IndexError('range object index out of range')
###?len(threadsList)
### 2
###
for	x in threadsList:
	# Create new thread
	currentThread = myThread(x, "Thread : {0}".format(x), x)
	# Start new Thread
	currentThread.start()
print("..........Exiting Main..........\n")

"""
Starting Thread : 0
..........Exiting Main..........
Thread [Thread : 0] Sleeping [1] Counter [5]

Starting Thread : 1
Thread [Thread : 1] Sleeping [2] Counter [5]
Thread : 0: Sat Aug 30 10:06:52 2025
Thread [Thread : 0] Sleeping [1] Counter [4]
Thread : 1: Sat Aug 30 10:06:53 2025
Thread : 0: Sat Aug 30 10:06:53 2025Thread [Thread : 1] Sleeping [2] Counter [4]

Thread [Thread : 0] Sleeping [1] Counter [3]
Thread : 0: Sat Aug 30 10:06:54 2025
Thread [Thread : 0] Sleeping [1] Counter [2]
Thread : 1: Sat Aug 30 10:06:55 2025
Thread [Thread : 1] Sleeping [2] Counter [3]
Thread : 0: Sat Aug 30 10:06:55 2025
Thread [Thread : 0] Sleeping [1] Counter [1]
Thread : 0: Sat Aug 30 10:06:56 2025
Exiting Thread : 0
Thread : 1: Sat Aug 30 10:06:57 2025
Thread [Thread : 1] Sleeping [2] Counter [2]
Thread : 1: Sat Aug 30 10:06:59 2025
Thread [Thread : 1] Sleeping [2] Counter [1]
Thread : 1: Sat Aug 30 10:07:01 2025
Exiting Thread : 1
"""