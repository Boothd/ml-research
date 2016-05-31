import numpy;
from numpy import recfromcsv;
from sklearn import tree;
from sklearn.externals.six import StringIO;
from sklearn.externals.six import StringIO  
import pydot 


from sklearn.datasets import load_iris


##
# Function takes an array of ports and returns the range as an int.
##
def getRange(ports):
	ports.sort();
	min = int(ports[0]);
	index=1;

	#not sure about this bit?
	while isinstance(len(ports)-index, int) != True:
		index=index+1;

	max = int(ports[len(ports)-index]);
	range = max-min;
	return range;

##
# Function takes an array of ports and returns the Standard Deviation.
##
def getSD(ports):
	return numpy.std(ports);

##
# Function an array of ports and returns the total number of ports in the array.
##
def getTotal(ports):
	return len(ports);

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

##
# Converts a String to an int.
##
def convertToInt(i):
	try:
		return int(i);
	except ValueError:
		return ;


def main():
	# iris = load_iris();
	# print(iris.target);
	# print(iris.data);

	data = recfromcsv('sample.csv', delimiter=',', skip_header=0);
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


	samples = [];
	posiblePortScanButProbablyNot = createFeatureArray(hashMap[134743044]);
	notAPortScan1 = createFeatureArray(hashMap[175636512]);
	notAPortScan2 = createFeatureArray(hashMap[175753235]);
	portScan = createFeatureArray(hashMap[173693690]);
	portScan = numpy.array(portScan).astype(int);

	samples.append(posiblePortScanButProbablyNot);
	samples.append(notAPortScan1);
	samples.append(notAPortScan2);
	samples.append(portScan);
	samples = numpy.array(samples).astype(int);


	clf = tree.DecisionTreeClassifier()
	clf = clf.fit(samples, [0,0,0,1]);


	with open("portScan.dot", 'w') as f:
		f = tree.export_graphviz(clf, out_file=f)

	dot_data = StringIO() 
	tree.export_graphviz(clf, out_file=dot_data) 
	graph = pydot.graph_from_dot_data(dot_data.getvalue()) 
	graph.write_pdf("portScan.pdf") 

	#os.unlink('portScan.dot');

	#generate matrix containing three features for each IP; total, range, SD.
	#use 2886753021 and 173693690 as training set.
	#run against all the data?
	#probably need more data!

main();