# This is a version simple program to show how HMM could be applied to DOS attacks given know
# precursor events, in this example we are using one precursor, but there could be multiple.
# the precusrors could be linked to each other or independant.
# 
#
# The program requires the installation of anaconda, sci-kit learn and hmmlearn.
# I would recommend installing in that order.

from __future__ import division
import numpy as np
from hmmlearn import hmm

#Know states that the model could be in,
#The algorithm will predict which state it is in given a chaning set of observations
states = ['ALL_IS_WELL', 'PRECURSOR_1', 'UNDER_ATTACK']
n_states = len(states)

#NORM = normality
#URL = increased traffic to single url
#HEADER =  increase in trafffic with header anomalies
#RESOURCE = increase resource usage
observations = ['NORM', 'URL', 'HEADER', 'RESOURCE']
n_observations = len(observations)

start_probability = np.array([0.8, 0.15, 0.05])

# The probability of transitioning from one state to another,
# ie ALL_IS_WELL to PRECURSOR_1
#
# 'ALL_IS_WELL'	: {'ALL_IS_WELL': p, 'PRECURSOR_1':p, 'UNDER_ATTACK':p },
# 'PRECURSOR_1'	: {'ALL_IS_WELL': p, 'PRECURSOR_1':p, 'UNDER_ATTACK':p },
# 'UNDER_ATTACK': {'ALL_IS_WELL': p, 'PRECURSOR_1':p, 'UNDER_ATTACK':p }
transition_probability = np.array([
	[0.7, 0.25, 0.05],
	[0.7, 0.2, 0.1],
	[0.1, 0.2, 0.7]
])

# The probability that given a certain emission event, we are in  a given state.
# ie probability p that given a RESOURCE event (increase in resource usage) is the state
# ALL_IS_WELL, PRECURSOR_1 or UNDER_ATTACK
#
# 'ALL_IS_WELL': {'NORM': p, 'URL':p, 'HEADER':p, 'RESOURCE':p },
# 'PRECURSOR_1'		: {'NORM': p, 'URL':p, 'HEADER':p, 'RESOURCE':p },
# 'UNDER_ATTACK'	: {'NORM': p, 'URL':p, 'HEADER':p, 'RESOURCE':p },
emission_probability = np.array([
	[0.6, 0.2, 0.1, 0.1],
	[0.2, 0.3, 0.3, 0.2],
	[0.05,0.2, 0.15,0.6],
])

model = hmm.MultinomialHMM(n_components=n_states)
model.startprob_ = start_probability
model.transmat_ = transition_probability
model.emissionprob_ =emission_probability 

# Predict a sequence of hidden states based on visible states
# These observations could be streamed into the application from another machine learning process.
observed_state_over_times = [0, 1, 2, 0, 2, 3, 3, 1]

#predict the state after each observation.
logprob, situation = model.decode(np.array(observed_state_over_times).reshape(-1,1), algorithm="viterbi")
print "Observations of state over time: ", ", ".join(map(lambda x: observations[x], observed_state_over_times))
print "Most like situation:", ", ".join(map(lambda x: states[x], situation))