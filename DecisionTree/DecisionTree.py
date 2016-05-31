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
# Python code which builds a decision tree from a simple sample set of data of port scans.
# Run the code by passing in the name of a csv file you would like the code to make a 
# prediction of possible port scan attacks against.
# The program will return the IP Address it thinks are being scanned.
# Currently using Range SD and Total as the features for the network data.
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
	return len(ports);
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

def test():
	array = (0, 0, 1, 0, 1, 0, 1, 1, 0);
	print(array);
	for index, val in enumerate(array):
	 	if val == 1:
	 		print(index);

def createTrainingSet(file):
	hashMap = csvToHashMap(file);

	samples = [];
	posiblePortScanButProbablyNot = createFeatureArray(hashMap[134743044]);
	notAPortScan1 = createFeatureArray(hashMap[175636512]);
	notAPortScan2 = createFeatureArray(hashMap[175753235]);
	portScan = createFeatureArray(hashMap[173693690]);
	portScan2 = createFeatureArray(hashMap[168430330]);

	#make sure all fields are ints.
	portScan = numpy.array(portScan).astype(int);

	samples.append(posiblePortScanButProbablyNot);
	samples.append(notAPortScan1);
	samples.append(notAPortScan2);
	samples.append(portScan);
	samples.append(portScan2);

	#make sure all fields are ints.
	samples = numpy.array(samples).astype(int);

	clf = tree.DecisionTreeClassifier();
	clf = clf.fit(samples, [0,0,0,1,1]);
	return clf;

def saveFile(object, fileName):
	trainingSet = open(fileName, 'w');
	pickle.dump(object, trainingSet);
	trainingSet.close();

def loadFile(fileName):
	return pickle.load(open(fileName, 'r'));


def main():
	
	csvFileName = sys.argv[1];
	
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
			print(featureArray[0][index]);

main();