###	#
###	### -••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••
###	### -••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••
###	### -••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••
###	#
###	if		self.__RetrieveCataloguesFromSOARdb()			==	True	\
###		and	self.__RetrieveAlertsToProcessFromSOARdb()		==	True:
###		#
###		if		self.__AletsToProcess_AsPandasDataFrame.empty		!=	True	\
###			and	len(self.__SOARcatalogues_AsPandasDataFrameList)	>	int(0):
###			if	len(self.__AletsToProcess_AsPandasDataFrame)	>	int(0):
###				#
###				threadsToWait		=	[]
###				soarMainThreadLock	=	threading.Lock()
###				#
###				super().logging_debug('Let''s begin process all alerts, count : {0} .....'.format(len(self.__AletsToProcess_AsPandasDataFrame)))
###				for rowIndex, rowAsSeries in self.__AletsToProcess_AsPandasDataFrame.iterrows():
###					# extract row as DataFrame
###					rowAsDataFrame		=		self.__AletsToProcess_AsPandasDataFrame.where(self.__AletsToProcess_AsPandasDataFrame['AlertId']	==	rowAsSeries['AlertId']).dropna(how = 'all')
###					# Create new thread worker
###					currentThread		=		SOARthreadProcessor(																																		\
###																			soarGlobalSettings						=	self._soarGlobalSettings															\
###																		,	soarCatalogues							=	self.__SOARcatalogues_AsPandasDataFrameList											\
###																		,	soarAlertConfigs_AsPandasDataFrame		=	rowAsDataFrame																		\
###																		,	threadID								=	rowIndex																			\
###																		,	threadName								=	'\u2022[{0}]\u2192{1}'.format(rowAsSeries['AlertId'], rowAsSeries['AlertName'])		\
###																		,	threadAlertCounter						=	int(rowAsSeries['AlertId'])															\
###																		,	varThreadLock							=	soarMainThreadLock																	\
###																	)
###					# Start new Thread
###					currentThread.start()
###					# Add thread to threadsToWait list
###					threadsToWait.append(currentThread)
###				# Wait for all threads to complete
###				for tW in threadsToWait:
###					tW.join()
###				#
###				super().logging_debug('..... Returned after wating for all threads completed')
###				#
###		#
###	#
###	### -••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••
###	### -••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••
###	### -••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••-••
###	#
