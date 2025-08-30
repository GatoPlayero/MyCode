import pyspark
from pyspark.sql import Row
from pyspark.sql import SparkSession
#
import pandas as pd
from datetime import datetime, date
#

### python -m ipykernel install --user --name AI --display-name "Anaconda Python (AI)"
### jupyter kernelspec list
### https://tech-depth-and-breadth.medium.com/setting-up-a-jupyter-kernel-in-visual-studio-code-using-conda-729f6bd3af8d

_spark = SparkSession.builder.master('local[1]').getOrCreate()

## _df = _spark.createDataFrame([Row(a=1, b=2., c='string1', d=date(2000, 1, 1), e=datetime(2000, 1, 1, 12, 0)),Row(a=2, b=3., c='string2', d=date(2000, 2, 1), e=datetime(2000, 1, 2, 12, 0)),Row(a=4, b=5., c='string3', d=date(2000, 3, 1), e=datetime(2000, 1, 3, 12, 0))])

_df = _spark.createDataFrame([
								Row(a=1, b=2., c='string1', d=date(2000, 1, 1), e=datetime(2000, 1, 1, 12, 0)),
								Row(a=2, b=3., c='string2', d=date(2000, 2, 1), e=datetime(2000, 1, 2, 12, 0)),
								Row(a=4, b=5., c='string3', d=date(2000, 3, 1), e=datetime(2000, 1, 3, 12, 0))
							])
_df.show(3)

###_newDF = _spark.read.csv("file:///C:/Users/Administrator/Documents/Code/Python/Spark/BigMart.Sales.csv", header=True, inferSchema=True, sep=",")
_newDF = _spark.read.format('csv').option('inferSchema', True).option('header',True).load("file:///C:/Users/Administrator/Documents/Code/Python/Spark/BigMart.Sales.csv")
_newDF.show(3)

## https://youtu.be/94w6hPk7nkM?feature=shared&t=05h50m17s

### https://youtu.be/1VBQmmdRQfM?si=SSWQLd29kkY2AiV0