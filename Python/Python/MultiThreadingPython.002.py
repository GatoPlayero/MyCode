import threading
import time

class myThread (threading.Thread):
	def __init__(self, threadID, name, counter, varThreadLock):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
		self.vThreadLock = varThreadLock
	def run(self):
		print("Starting " + self.name)
		self.my_print_time(self.name, 5, self.counter)
		#
		#
		# A primitive lock is a synchronization primitive that is not owned by a particular thread when locked. In Python,
		# it is currently the lowest level synchronization primitive available, implemented directly by the _thread extension module.
		#
		# A primitive lock is in one of two states, •locked• or •unlocked•. It is created in the unlocked state.
		# It has two basic methods, acquire() and release(). When the state is unlocked, acquire() changes the state to locked and returns immediately.
		# When the state is locked, acquire() blocks until a call to release() in another thread changes it to unlocked,
		# then the acquire() call resets it to locked and returns. The release() method should only be called in the locked state;
		# it changes the state to unlocked and returns immediately. If an attempt is made to release an unlocked lock, a RuntimeError will be raised.
		#
		#
		# Get lock to synchronize threads
		self.vThreadLock.acquire()
		print("Exiting " + self.name)
		# Free lock to release next thread
		self.vThreadLock.release()
		#
	def my_print_time(self, threadName, counter, delay):
		while counter:
			print("Thread [{0}] Sleeping [{1}] Counter [{2}]".format(threadName, delay+1, counter))
			time.sleep(delay+1)
			print("%s: %s" % (threadName, time.ctime(time.time())))
			counter -= 1



threadsToWait = []
externalThreadLock = threading.Lock()	
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
	currentThread = myThread(x, "Thread : 0{0}".format(x), x, externalThreadLock)
	# Start new Thread
	currentThread.start()
	# Add thread to threadsToWait list
	threadsToWait.append(currentThread)
print("..........Running on Main\n")
# Wait for all threads to complete
for t in threadsToWait:
	t.join()
print("Exiting Main Thread..........")

"""
..........Running on Main
Starting Thread : 00
Starting Thread : 01

Thread [Thread : 00] Sleeping [1] Counter [5]Thread [Thread : 01] Sleeping [2] Counter [5]

Thread : 00: Sat Aug 30 10:08:34 2025
Thread [Thread : 00] Sleeping [1] Counter [4]
Thread : 01: Sat Aug 30 10:08:35 2025
Thread [Thread : 01] Sleeping [2] Counter [4]
Thread : 00: Sat Aug 30 10:08:35 2025
Thread [Thread : 00] Sleeping [1] Counter [3]
Thread : 00: Sat Aug 30 10:08:36 2025
Thread [Thread : 00] Sleeping [1] Counter [2]
Thread : 01: Sat Aug 30 10:08:37 2025
Thread [Thread : 01] Sleeping [2] Counter [3]
Thread : 00: Sat Aug 30 10:08:37 2025
Thread [Thread : 00] Sleeping [1] Counter [1]
Thread : 00: Sat Aug 30 10:08:38 2025
Exiting Thread : 00
Thread : 01: Sat Aug 30 10:08:39 2025
Thread [Thread : 01] Sleeping [2] Counter [2]
Thread : 01: Sat Aug 30 10:08:41 2025
Thread [Thread : 01] Sleeping [2] Counter [1]
Thread : 01: Sat Aug 30 10:08:43 2025
Exiting Thread : 01
Exiting Main Thread..........
"""