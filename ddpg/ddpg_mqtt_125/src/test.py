#!/usr/bin/env python3
# Author: Aron Laszka, Liang Tong

"""Test instances for the alert prioritization model."""

from model import PoissonDistribution, AlertType, AttackType, Model
import numpy as np
import sys

EPSILON = 0.00001

def test_model_fraud(def_budget, adv_budget):
  """
  Creat a test model by using the credit fraud dataset (H = 1, |T| = 6, |A| = 6).
  :return: Model object. 
  """
  alert_types =  [AlertType(1.0, PoissonDistribution(10), "t1"), 
                  AlertType(1.0, PoissonDistribution(47), "t4"),
                  AlertType(1.0, PoissonDistribution(39), "t6")]
  attack_types = [AttackType([9.374], 1, [1.0*0.9, 0.67*0.9, 0.0], "a1"),
                  AttackType([12.14], 3, [0.01*0.9, 0.96*0.9, 0.13*0.9], "a4"),
                  AttackType([16.03], 2, [0.0, 0.45*0.9, 0.94*0.9], "a6")]
  model = Model(1, alert_types, attack_types, def_budget, adv_budget)
  return model
"""
def test_model_snort(def_budget, adv_budget):
  
  alert_types =  [AlertType(1.0, PoissonDistribution(215900), "t1"), 
                  AlertType(1.0, PoissonDistribution(100), "t2"),
                  AlertType(1.0, PoissonDistribution(2200), "t3"),
                  AlertType(1.0, PoissonDistribution(1200), "t4")]
  attack_types = [AttackType([1.4], 80.0, [816,0,0,0], "a1"),
                  AttackType([1.4], 60.0, [0,259,0,0], "a2"),
                  AttackType([4.3], 20.0, [0,92,0,0], "a3"),
                  AttackType([5.5], 74.0, [0,0,141,0], "a4")]
  #model = Model(1, alert_types, attack_types, 1000.0, 120.0)
  model = Model(1, alert_types, attack_types, def_budget, adv_budget)
  return model
"""
def test_model_snort(def_budget, adv_budget):
  
  alert_types =  [AlertType(1.0, PoissonDistribution(10274000), "t1"), 
                  AlertType(1.0, PoissonDistribution(0), "t2")]
  attack_types = [AttackType([3.6], 135.0, [862,0], "a1"),
                  AttackType([1.4], 25.0, [18785,281], "a2")]
  #model = Model(1, alert_types, attack_types, 1000.0, 120.0)
  model = Model(1, alert_types, attack_types, def_budget, adv_budget)
  return model

def test_model_suricata(def_budget, adv_budget):
  """
  Creat a test model by using the IDS dataset (H = 1, |T| = 7, |A| = 7).
  :return: Model object. 
  """
  alert_types =  [AlertType(1.0, PoissonDistribution(7200), "t1"), 
                  AlertType(1.0, PoissonDistribution(44100), "t2"),
                  AlertType(1.0, PoissonDistribution(1600), "t3"),
                  AlertType(1.0, PoissonDistribution(7300), "t4"),
                  AlertType(1.0, PoissonDistribution(17400), "t5"),
                  AlertType(1.0, PoissonDistribution(4000), "t6"),
                  AlertType(1.0, PoissonDistribution(10200), "t7")]
  attack_types = [AttackType([3.6], 120.0, [1230,0,0,0,0,0,0], "a1"),
                  AttackType([6.0], 60.0, [0,4,2,106,0,54,0], "a2"),
                  AttackType([4.0], 74.0, [0,0,0,0,0,24,0], "a3"),
                  AttackType([3.6], 20.0, [0,0,4,0,10,0,0], "a4"),
                  AttackType([1.4], 52.0, [710,2,862,12,0,80,600], "a5"),
                  AttackType([1.4], 80.0, [138,0,320,30,0,0,0], "a6"),
                  AttackType([2.7], 62.0, [0,0,6,0,0,0,0], "a7")]
  #model = Model(1, alert_types, attack_types, 1000.0, 120.0)
  model = Model(1, alert_types, attack_types, def_budget, adv_budget)
  return model

def test_defense_action(model, state):
  """
  Compute a basic investigation action (i.e., number of alerts to investigate), which distributes the defender's budget uniformly among alert types and ages.
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """
  budget = model.def_budget / (model.horizon * len(model.alert_types))
  delta = []
  for h in range(model.horizon):
    delta.append([min(int(budget / model.alert_types[t].cost), state.N[h][t]) for t in range(len(model.alert_types))])
  return delta

def test_defense_newest(model, state):
  """
  Compute a basic investigation action (i.e., number of alerts to investigate), which distributes the defender's budget uniformly among newest alert.
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """
  budget_for_newest = model.def_budget / len(model.alert_types) # We distribute the budget to the newest alerts
  delta = []
  for h in range(model.horizon):
    if h == 0:
      delta.append([min(int(budget_for_newest / model.alert_types[t].cost), state.N[h][t]) for t in range(len(model.alert_types))])
    else:
      delta.append([0] * len(model.alert_types))
  return delta

def test_defense_proportion(model, state):
  delta = []
  n_alerts = np.array(state.N[0]) + 0.000001
  ratio = n_alerts/np.sum(n_alerts)
  delta.append([min(int(model.def_budget*ratio[t] / model.alert_types[t].cost), state.N[0][t]) for t in range(len(model.alert_types))])
  return delta	

def test_defense_fraud(model, state):
  """
  Compute a basic investigation action (i.e., number of alerts to investigate), which distributes the defender's budget on some specific alerts.
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """  
  delta = []
  means = [0, 17, 0, 14, 23] # The mean of each false positive alert types
  ratio = np.array(means)/np.sum(means)
  for h in range(model.horizon):
    if h == 0:
      delta.append([min(int(model.def_budget*ratio[t] / model.alert_types[t].cost), state.N[h][t]) for t in range(len(model.alert_types))])
    else:
      delta.append([0] * len(model.alert_types))
  return delta

def test_defense_snort(model, state):
  """
  Compute an investigation action based on the built-in priorities of Suricata
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """
  delta = []
  for h in range(model.horizon):
    delta.append([0]*len(model.alert_types))
  remain_budget = model.def_budget
  used_budget = 0.0
  #alert_priority = np.array([2,1,2,3,3,1,3,1,1,1])
  alert_priority = np.array([3,2])
  for i in range(np.unique(alert_priority).shape[0]):
    if remain_budget > 0:
      index_priority = np.where(alert_priority == i+1)[0]
      for j in index_priority:
        delta[0][j] = min(int(remain_budget / index_priority.shape[0] / model.alert_types[j].cost), state.N[0][j])
        used_budget += delta[0][j] * model.alert_types[j].cost
      remain_budget = model.def_budget - used_budget
    else:
      break
  return delta

def test_defense_suricata(model, state):
  """
  Compute an investigation action based on the built-in priorities of Suricata
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """
  delta = []
  for h in range(model.horizon):
    delta.append([0]*len(model.alert_types))
  remain_budget = model.def_budget
  used_budget = 0.0
  #alert_priority = np.array([2,1,2,3,3,1,3,1,1,1])
  alert_priority = np.array([2,1,2,3,3,1,3])
  for i in range(np.unique(alert_priority).shape[0]):
    if remain_budget > 0:
      index_priority = np.where(alert_priority == i+1)[0]
      for j in index_priority:
        delta[0][j] = min(int(remain_budget / index_priority.shape[0] / model.alert_types[j].cost), state.N[0][j])
        used_budget += delta[0][j] * model.alert_types[j].cost
      remain_budget = model.def_budget - used_budget
    else:
      break
  return delta

def test_defense_aics(model, state):
  """
  Compute an investigation action based on the aics implementation
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """
  delta = []
  for h in range(model.horizon):
    delta.append([0]*len(model.alert_types))
  remain_budget = model.def_budget
  used_budget = 0.0

  if model.def_budget == 20:
    prio_profile, prob_profile = [[3, 1, 2], [2, 3, 1]], [0.20295405010983106, 0.7970459498901689]
  elif model.def_budget == 30:
    prio_profile, prob_profile = [[3, 1, 2], [2, 3, 1]], [0.6140734776822184, 0.38592652231778135]
  elif model.def_budget == 40:
    prio_profile, prob_profile = [[3, 1, 2], [2, 3, 1]], [0.622029540310321, 0.3779704596896787]
  elif model.def_budget == 5:
  	prio_profile, prob_profile = [[2, 3, 1]], [1.0]
  elif model.def_budget == 10:
  	prio_profile, prob_profile = [[3, 2, 1]], [1.0]
  elif model.def_budget == 15:
  	prio_profile, prob_profile = [[3, 2, 1]], [1.0]

  ind = np.random.choice(len(prio_profile), p=prob_profile)
  alert_priority = np.array(prio_profile[ind]) 

  for i in range(np.unique(alert_priority).shape[0]):
    if remain_budget > 0:
      index_priority = np.where(alert_priority == i+1)[0]
      for j in index_priority:
        delta[0][j] = min(int(remain_budget / index_priority.shape[0] / model.alert_types[j].cost), state.N[0][j])
        used_budget += delta[0][j] * model.alert_types[j].cost
      remain_budget = model.def_budget - used_budget
    else:
      break
  return delta

def test_defense_icde(model, state):
  """
  Compute an investigation action based on the icde implementation
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Number of alerts to investigate. Two-dimensional array, delta[h][t] is the number of alerts to investigate of type t raised h time steps ago.
  """
  delta = []
  for h in range(model.horizon):
    delta.append([0]*len(model.alert_types))
  remain_budget = model.def_budget
  used_budget = 0.0

  if model.def_budget == 20:
    prio_profile, prob_profile, threshold = [[1, 3, 2], [3, 1, 2], [2, 3, 1]], [0.24, 0.48, 0.28], [1, 8, 18]
  elif model.def_budget == 30:
    prio_profile, prob_profile, threshold = [[1, 3, 2], [3, 1, 2], [2, 3, 1]], [0.6, 0.06, 0.34], [2, 11, 25]
  elif model.def_budget == 40:
    prio_profile, prob_profile, threshold = [[1, 3, 2], [3, 1, 2], [2, 3, 1]], [0.62, 0.25, 0.13], [4, 16, 23]
  elif model.def_budget == 5:
  	prio_profile, prob_profile, threshold = [[1, 2, 3]], [1.0], [0, 0, 63]
  elif model.def_budget == 10:
  	prio_profile, prob_profile, threshold = [[1, 2, 3]], [1.0], [0, 0, 63]
  elif model.def_budget == 15:
  	prio_profile, prob_profile, threshold = [[1, 3, 2], [3, 1, 2]], [0.73, 0.27], [0, 3, 63]

  ind = np.random.choice(len(prio_profile), p=prob_profile)
  alert_priority = np.array(prio_profile[ind]) 

  for i in range(np.unique(alert_priority).shape[0]):
    if remain_budget > 0:
      index_priority = np.where(alert_priority == i+1)[0]
      for j in index_priority:
        delta[0][j] = min(int(remain_budget / index_priority.shape[0] / model.alert_types[j].cost), state.N[0][j], threshold[j])
        used_budget += delta[0][j] * model.alert_types[j].cost
      remain_budget = model.def_budget - used_budget
    else:
      break
  return delta

def test_attack_action(model, state):
  """
  Compute a basic attack action (i.e., probability of mouting attacks), which distributes the adversary's budget uniformly among attack types.
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Probability of mounting attacks. One-dimensional array, alpha[a] is the probability of mounting an attack of type a.
  """
  #budget = model.adv_budget / len(model.attack_types)
  budget = model.adv_budget / len(model.attack_types)
  alpha = [min(budget / a.cost, 1) for a in model.attack_types]
  return alpha
def test_attack_action1(model, state):
  """
  Compute a basic attack action (i.e., probability of mouting attacks), which distributes the adversary's budget uniformly among attack types.
  :param model: Model of the alert prioritization problem (i.e., Model object).
  :param state: State of the alert prioritization problem (i.e., Model.State object).
  :return: Probability of mounting attacks. One-dimensional array, alpha[a] is the probability of mounting an attack of type a.
  """
  #budget = model.adv_budget / len(model.attack_types)
  #budget = model.adv_budget / len(model.attack_types)
  alpha = [0,1]
  return alpha
def test_attack_aics(model, state):
  if model.def_budget == 10 or model.def_budget == 20:
    if model.adv_budget == 2:
      alpha = [0, 0, 1]
    if model.adv_budget == 3:
      alpha = [1, 0, 1]
  elif model.def_budget == 30:
    if model.adv_budget ==2:
      alpha = [0, 0, 1]
    if model.adv_budget == 3:
      alpha = [0, 0.33, 1]        
  return alpha

def test_attack_ids(model, state):
  #alpha = [0, 1, 0.54, 1, 0, 0, 0]
  alpha = [0, 0, 1, 1, 0, 0 , 0.419]
  return alpha

def test_attack_snort(model, state):
  #alpha = [1, 1, 0.54, 0]
  alpha = [0.4,1]
  return alpha

def test_model_from_alerts(alert_file_path, def_budget, adv_budget):
  """
  Create a test model from alert_json.txt file (real-time Snort data).
  This function uses alert_json_loader to build the model dynamically.
  Uses classification and priority from Snort alerts.
  :param alert_file_path: Path to alert_json.txt file
  :param def_budget: Defender budget
  :param adv_budget: Adversary budget
  :return: Model object
  """
  from alert_json_loader import create_model_from_alerts
  return create_model_from_alerts(alert_file_path, def_budget, adv_budget)


def test_model_realtime(def_budget, adv_budget):
  """
  Create a test model for real-time DDPG with all 10 attack types from local.rules.
  Uses predefined parameters based on attack severity.
  :param def_budget: Defender budget
  :param adv_budget: Adversary budget
  :return: Model object
  """
  # 10 alert types corresponding to 10 attack types
  alert_types = [
      AlertType(1.0, PoissonDistribution(100), "t1_SYN_FLOOD"),
      AlertType(1.0, PoissonDistribution(50), "t2_SQL_INJECTION"),
      AlertType(1.0, PoissonDistribution(30), "t3_HTTP_C2"),
      AlertType(1.0, PoissonDistribution(200), "t4_PORT_SCAN"),
      AlertType(1.0, PoissonDistribution(80), "t5_BRUTE_FORCE"),
      AlertType(1.0, PoissonDistribution(150), "t6_DDOS"),
      AlertType(1.0, PoissonDistribution(40), "t7_XSS"),
      AlertType(1.0, PoissonDistribution(25), "t8_COMMAND_INJECTION"),
      AlertType(1.0, PoissonDistribution(20), "t9_MALWARE_DOWNLOAD"),
      AlertType(1.0, PoissonDistribution(60), "t10_DNS_TUNNELING"),
  ]
  
  # 10 attack types with costs, losses, and alert probabilities
  # pr_alert: each attack primarily triggers its corresponding alert type
  attack_types = [
      AttackType([3.6], 80.0, [0.9, 0, 0, 0, 0, 0, 0, 0, 0, 0], "SYN_FLOOD"),
      AttackType([4.0], 60.0, [0, 0.9, 0, 0, 0, 0, 0, 0, 0, 0], "SQL_INJECTION"),
      AttackType([5.5], 74.0, [0, 0, 0.9, 0, 0, 0, 0, 0, 0, 0], "HTTP_C2"),
      AttackType([1.4], 20.0, [0, 0, 0, 0.9, 0, 0, 0, 0, 0, 0], "PORT_SCAN"),
      AttackType([2.7], 52.0, [0, 0, 0, 0, 0.9, 0, 0, 0, 0, 0], "BRUTE_FORCE"),
      AttackType([4.3], 135.0, [0, 0, 0, 0, 0, 0.9, 0, 0, 0, 0], "DDOS"),
      AttackType([3.0], 40.0, [0, 0, 0, 0, 0, 0, 0.9, 0, 0, 0], "XSS"),
      AttackType([4.5], 65.0, [0, 0, 0, 0, 0, 0, 0, 0.9, 0, 0], "COMMAND_INJECTION"),
      AttackType([5.0], 90.0, [0, 0, 0, 0, 0, 0, 0, 0, 0.9, 0], "MALWARE_DOWNLOAD"),
      AttackType([2.5], 45.0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0.9], "DNS_TUNNELING"),
  ]
  
  model = Model(1, alert_types, attack_types, def_budget, adv_budget)
  return model


def test_defense_realtime(model, state):
  """
  Compute investigation action for real-time alerts based on attack severity.
  Prioritizes high-loss attacks (HTTP_C2, MALWARE_DOWNLOAD, COMMAND_INJECTION, DDOS).
  """
  delta = []
  for h in range(model.horizon):
    delta.append([0] * len(model.alert_types))
  
  remain_budget = model.def_budget
  used_budget = 0.0
  
  # Priority order based on attack loss (higher loss = investigate first)
  # Indices: HTTP_C2(2), MALWARE_DOWNLOAD(8), COMMAND_INJECTION(7), DDOS(5), 
  #          SQL_INJECTION(1), SYN_FLOOD(0), XSS(6), BRUTE_FORCE(4), DNS_TUNNELING(9), PORT_SCAN(3)
  priority_order = [2, 8, 7, 5, 1, 0, 6, 4, 9, 3]
  
  for idx in priority_order:
    if remain_budget > 0 and idx < len(model.alert_types):
      delta[0][idx] = min(
          int(remain_budget / model.alert_types[idx].cost),
          state.N[0][idx]
      )
      used_budget += delta[0][idx] * model.alert_types[idx].cost
      remain_budget = model.def_budget - used_budget
  
  return delta


def test_attack_realtime(model, state):
  """
  Compute attack action for real-time scenario.
  Focuses on cost-effective attacks with high loss-to-cost ratio.
  """
  # Loss-to-cost ratios for each attack type
  alpha = [0.0] * len(model.attack_types)
  
  for i, at in enumerate(model.attack_types):
    ratio = at.loss[0] / at.cost
    alpha[i] = min(ratio * 10, 1.0)  # Scale and cap at 1.0
  
  # Normalize to budget
  total_cost = sum(model.attack_types[i].cost * alpha[i] for i in range(len(alpha)))
  if total_cost > model.adv_budget:
    factor = model.adv_budget / total_cost
    alpha = [a * factor for a in alpha]
  
  return alpha

if __name__ == "__main__":
  model = test_model_snort(1000, 125)
  state = Model.State(model)
  #print(test_defense_action(model, state))
  #print(test_attack_action(model, state))
  i = 0
  while i < 10:
    print('#############################')
    print(i)
    print('state:', state)
    print('attacker:', test_attack_action(model, state))
    state = model.next_state('old', state, test_defense_action, test_attack_action)
    i += 1

