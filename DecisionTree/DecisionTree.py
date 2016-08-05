import numpy;
from numpy import recfromcsv;
from sklearn import tree;
from sklearn.externals.six import StringIO;
from sklearn.externals.six import StringIO;
import sys;
import pickle;
#import pydot;

##
# Author: D Booth
# Usage DecisionTree.py <traffic.csv>
#
# SK Learn Algorithm which implements a decision tree from a simple sample set of data 
# of port scans.
# Run the code by passing in the name of a csv file, the algorithm will make a  
# prediction of possible port scan attacks in the data set.
# The algorithm will return the IP Address it thinks are being scanned.
# Currently using Range, SD and Total as the features for the network data.
# 
# Requirements: Python2.7, Anaconda 1.2.1, 
##


##
# Function takes an array of ports and returns the range as an int.
##
def getRange(ports):
	# try:
	ports.sort();
	min = int(ports[0]);
	index=1;

	#not sure about this bit?
	while isinstance(len(ports)-index, int) != True:
		index=index+1;

	max = int(ports[len(ports)-index]);
	range = max-min;
	return range;
	# except (ValueError,IndexError):
	# 	print(ports);
	# 	exit(1);
#getRange

##
# Function takes an array of ports and returns the Standard Deviation.
##
def getSD(ports):
	return numpy.std(ports);
#getSD

##
# Function an array of ports and returns the total number of ports in the array.
##
def getTotal(ports):
	return len(numpy.unique(ports));
	#return len(ports);
#getTotal

##
# Function takes an array of ports and returns an array of features.
# Current the feature set is:
# Range, Total and SD.
##
def createFeatureArray(ports):
	features = [];
	features.append(getRange(ports));
	features.append(getTotal(ports));
	features.append(getSD(ports));
	return features;
#createFeatureArray

##
# Converts a String to an int.
##
def convertToInt(i):
	try:
		return int(i);
	except ValueError:
		# print("Error handinging "+str(i));
		return ;
#convertToInt

##
# Not very useful graph function.
##
def createGraph(clf):
	with open("portScan.dot", 'w') as f:
		f = tree.export_graphviz(clf, out_file=f)

	dot_data = StringIO() 
	tree.export_graphviz(clf, out_file=dot_data) 
	graph = pydot.graph_from_dot_data(dot_data.getvalue()) 
	graph.write_pdf("portScan.pdf") 
#createGraph	

def csvToHashMap(csvFile):
	data = recfromcsv(csvFile, delimiter=',', skip_header=0);
	data.dtype.names = ('Protocol',	'Time',	'Source IP','Desination IP','Source Port','Destination Port','Time to Live','Length','Fragments','Flags');
	SOURCE_IP = 2;
	DESTINATION_IP = 5;
	#build map, where ip is the key and destination ports are pushed into an array.
	hashMap = {};

	for i in data:
		if i[SOURCE_IP] in hashMap:
			port = convertToInt(i[DESTINATION_IP]);
			if type(port) == int:
				hashMap.get(i[SOURCE_IP]).append(port);
		else:
			hashMap[i[SOURCE_IP]] = [];	

	return hashMap;
#csvToHashMap

def csvToHashMapNoHeaders(csvFile):
	data = recfromcsv(csvFile, delimiter=',', skip_header=0);
	SOURCE_IP = 3;
	DESTINATION_IP = 6;
	#build map, where ip is the key and destination ports are pushed into an array.
	hashMap = {};

	for i in data:
		if i[SOURCE_IP] in hashMap:
			port = convertToInt(i[DESTINATION_IP]);
			if type(port) == int:
				hashMap.get(i[SOURCE_IP]).append(port);
		else:
			hashMap[i[SOURCE_IP]] = [];	
			port = convertToInt(i[DESTINATION_IP]);
			if type(port) == int:
				hashMap.get(i[SOURCE_IP]).append(port);
	# print("******");
	# print(hashMap[168820738]);
	return hashMap;
#csvToHashMap

def hashMapToFeatureArray(hashMap):
	featureArray = [];
	featureArray.append([]);
	featureArray.append([]);
	for key in hashMap:
		features=[];
		try:
			features = createFeatureArray(hashMap[key]);
		except (ValueError,IndexError):
			print("Key: "+str(key)+" "+str(hashMap[key]));

		featureArray[0].append(key);
		featureArray[1].append(features);
	#for
	featureArray[1] = numpy.array(featureArray[1]).astype(int);
	return featureArray;
#hashMapToFeatureArray

def test():
	array = (0, 0, 1, 0, 1, 0, 1, 1, 0);
	print(array);
	for index, val in enumerate(array):
	 	if val == 1:
	 		print(index);

def printFeatureArray(port, array):
	print(str(port)+": "+str(array));


def createTrainingSet(file):
	hashMap = csvToHashMap(file);

	samples = [];
	posiblePortScanButProbablyNot = createFeatureArray(hashMap[134743044]);
	printFeatureArray(str(134743044),str(posiblePortScanButProbablyNot));

	notAPortScan1 = createFeatureArray(hashMap[175636512]);
	printFeatureArray(str(175636512),str(notAPortScan1));

	notAPortScan2 = createFeatureArray(hashMap[175753235]);
	printFeatureArray(str(175753235),str(notAPortScan2));

	portScan = createFeatureArray(hashMap[173693690]);
	printFeatureArray(str(175636489),str(portScan));

	portScan2 = createFeatureArray(hashMap[168430330]);
	printFeatureArray(str(168430330),str(portScan2));

	notAPortScan3 = createFeatureArray(hashMap[178916423]);
	printFeatureArray(str(178916423),str(notAPortScan3));
	
	notAPortScan4 = createFeatureArray(hashMap[175636489]);
	printFeatureArray(str(175636489),str(notAPortScan4));


	#make sure all fields are ints.
	#portScan = numpy.array(portScan).astype(int);

	samples.append(posiblePortScanButProbablyNot);
	samples.append(notAPortScan1);
	samples.append(notAPortScan2);
	samples.append(portScan);
	samples.append(portScan2);
	samples.append(notAPortScan3);
	samples.append(notAPortScan4);

	#make sure all fields are ints.
	samples = numpy.array(samples).astype(int);

	clf = tree.DecisionTreeClassifier();
	clf = clf.fit(samples, [0,0,0,1,1,0,0]);
	return clf;
#createTrainingSet

def saveFile(object, fileName):
	trainingSet = open(fileName, 'w');
	pickle.dump(object, trainingSet);
	trainingSet.close();

def loadFile(fileName):
	return pickle.load(open(fileName, 'r'));

def from_string(s):
  "Convert dotted IPv4 address to integer."
  return reduce(lambda a,b: a<<8 | b, map(int, s.split(".")))

def to_string(ip):
  "Convert 32-bit integer to dotted IPv4 address."
  return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))

  


def main():
	
	if(sys.version_info > (3,0)):
		print("Script has detected that the python version is 3 or greater. "+
			"Please use python version 2.7 and Anaconda 2.4.1");
	else: 
		csvFileName = sys.argv[1];
		#hostIpsArray = sys.argv[2];
		
		print("Creating training set");
		clf = createTrainingSet('sample.csv');

		print("Processing: "+csvFileName);
		dayone21Hash = csvToHashMapNoHeaders(csvFileName);
		featureArray = hashMapToFeatureArray(dayone21Hash);

		print("Prediction port scans.");
		prediction = clf.predict(featureArray[1]);
		#print(prediction);
		#print(clf.predict_proba(featureArray))

		print("The following IP's are possible port scans.");
		for index, val in enumerate(prediction):
			if val == 1:
				print(str(featureArray[0][index])+" : "+to_string(featureArray[0][index]));

main();