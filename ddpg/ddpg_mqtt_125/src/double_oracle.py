#!/usr/bin/env python3
# Author: Liang Tong

from scipy import optimize as op
from listutils import *
from model import Model
from test import *
from listutils import *
import ddpg
from ddpg import DefenderOracle
from ddpg import AttackerOracle
from config import config

import multiprocessing
import numpy as np
import random
import logging
import pickle
import sys
import tensorflow as tf
import os

os.environ["TF_CPP_MIN_LOG_LEVEL"]='2'

"""Implementation of double-oracle algorithms."""

##################### CONFIGURATION ######################
MAX_EPISODES = config.getint('parameter', 'max_episodes')
MAX_STEPS = config.getint('parameter', 'max_ep_steps')
GAMMA = config.getfloat('parameter', 'gamma')
MAX_ITERATION = config.getint('double-oracle', 'max_iteration')
N_TRIAL = config.getint('double-oracle', 'n_trial')
##########################################################

def find_mixed_NE(payoff):
    """
    Function for returning mixed strategies of the first step of double oracle iterations.
    :param payoff: Two dimensinal array. Payoff matrix of the players. The row is defender and column is attcker. 
    :return: List, mixed strategy of the attacker and defender at NE by solving maxmini problem. 
    """ 
    # This implementation is based on page 88 of the book multiagent systems (Shoham etc.)
    n_action = payoff.shape[0]
    c = np.zeros(n_action)
    c = np.append(c, 1)
    A_ub = np.concatenate((payoff, np.full((n_action, 1), -1)), axis=1)
    b_ub = np.zeros(n_action)
    A_eq = np.full(n_action, 1)
    A_eq = np.append(A_eq, 0)
    A_eq = np.expand_dims(A_eq, axis=0)
    b_eq = np.array([1])
    bound = ()
    for i in range(n_action):
        bound += ((0, None),)
    bound += ((None, None),)
    res_attacker = op.linprog(c, A_ub, b_ub, A_eq, b_eq, bounds=bound)
    c = -c
    A_ub = np.concatenate((-payoff.T, np.full((n_action, 1), 1)), axis=1)
    res_defender = op.linprog(c, A_ub, b_ub, A_eq, b_eq, bounds=bound)
    return list(res_attacker.x[0:n_action]), list(res_defender.x[0:n_action]), res_attacker.fun

def get_payoff_mixed(model, attack_profile, defense_profile, attack_strategy, defense_strategy):
    """
    Function for computing the payoff of the defender given its mixed strategy and the mixed strategy of the attacker. 
    :param model: Model of the alert prioritization problem (i.e., Model object).
    :param attack_profile: List of attack policies.ks given a model and a state.
    :param defense_profile: List of defense policies.    
    :param attack_strategy: List of probablities of choosing policy from the attack profile 
    :param defense_strategy: List of probablities of choosing policy from the defense profile 
    :return: The expected discounted reward. 
    """
    total_discount_reward = 0
    
    attack_policies = np.random.choice(attack_profile, MAX_EPISODES, p=attack_strategy)
    defense_policies = np.random.choice(defense_profile, MAX_EPISODES, p=defense_strategy) 

    initial_state = Model.State(model)

    for i in range(MAX_EPISODES):
        state = initial_state
        episode_reward = 0.0
        defense_policy = defense_policies[i]
        attack_policy = attack_policies[i]
        for j in range(MAX_STEPS):
            next_state = model.next_state('old', state, defense_policy, attack_policy)
            loss = next_state.U - state.U
            state = next_state
            step_reward = -1.0*loss
            episode_reward += GAMMA**j*step_reward
        total_discount_reward += episode_reward
    ave_discount_reward = total_discount_reward/MAX_EPISODES
    return ave_discount_reward

def get_payoff(model, attack_policy, defense_policy):
    """
    Function for computing the payoff of the defender given its strategy and the strategy of the attacker. 
    :param model: Model of the alert prioritization problem (i.e., Model object).
    :param attack_policy: Function, takes a model and a state, returns the portion of budget allocated for each type of attacks given a model and a state.
    :param defense_policy: Function, takes a model and a state, returns the portion of budget allocated for each type of alerts with all ages given a model and a state.
    :return: The expected discounted reward. 
    """
    ave_discount_reward = get_payoff_mixed(model, [attack_policy], [defense_policy], [1.0], [1.0])	
    return ave_discount_reward

def update_profile(model, payoff, attack_profile, 
        defense_profile, attack_policy, defense_policy):
    """
    Function for updating the payoff matrix and the action profile of defender and attacker
    :param model: Model of the alert prioritization problem (i.e., Model object).
    :param payoff: Two dimensinal array. Payoff matrix of the players. The row is defender and column is attcker. 
    :param attack_profile: List of attack policies.
    :param defense_profile: List of defense policies.
    :param attack_policy: New pure strategy of the attacker
    :param defense_policy: New pure strategy of the defender
    :return: updated payoff matrix, attack_profile and defense_profile
    """
    n_action = payoff.shape[0]

    # A new row and column will be added to the payoff matrix    
    new_payoff_col = np.array([])
    new_payoff_row = np.array([])

    # First get the new column    
    for i in range(len(defense_profile)):
        new_payoff = get_payoff(model, attack_policy, defense_profile[i])
        new_payoff_col = np.append(new_payoff_col, new_payoff)
    new_payoff_col = np.expand_dims(new_payoff_col, axis=0)
    attack_profile.append(attack_policy)    
    payoff = np.concatenate((payoff, new_payoff_col.T), axis=1)

    # Second, get the new row
    for j in range(len(attack_profile)):
        new_payoff = get_payoff(model, attack_profile[j], defense_policy)
        new_payoff_row = np.append(new_payoff_row, new_payoff)
    new_payoff_row = np.expand_dims(new_payoff_row, axis=0)
    defense_profile.append(defense_policy)
    payoff = np.concatenate((payoff, new_payoff_row), axis=0)
    return payoff, attack_profile, defense_profile

def double_oracle(model, exper_index, model_dir):
    # Set the base directory for ddpg.py to use in this process
    ddpg.MODEL_BASE_DIR = model_dir
    
    #print("Initializing...")
    attack_profile = []
    defense_profile = []
    payoff = []
    payoff_record = []

    # Initialize the payoff matrix
    initial_payoff = get_payoff(model, test_attack_action, test_defense_newest)
    payoff = np.array([[initial_payoff]])
    # Initialize the action profile
    attack_profile = [test_attack_action]
    defense_profile = [test_defense_newest]
    initial_defense_size = payoff.shape[0]
    initial_attack_size = payoff.shape[1]    

    # Compute new strategies and actions
    for i in range(MAX_ITERATION):
        attack_strategy, defense_strategy, utility = find_mixed_NE(payoff)
        payoff_record.append(utility)

        print("###########################################################################################")
        print("Iteration", i)

        print("Current payoff matrix:")
        print(payoff)

        print("Attacker's mixed strategy:")
        print(attack_strategy)
        print("Defender's mixed strategy:")
        print(defense_strategy)

        logging.info("Iteration {}: {}".format(i, payoff_record))
        utility_defender_newest = np.dot(payoff[0], attack_strategy)
        utility_attacker_uniform = np.dot(payoff[:,0], defense_strategy)


        # Get new response to the mixed strategy
        attack_response = []
        attack_utility = []
        defense_response = []
        defense_utility = []
        for k in range(N_TRIAL):
            attack_response.append(AttackerOracle(model, defense_profile, defense_strategy, exper_index, i, k))
            defense_response.append(DefenderOracle(model, attack_profile, attack_strategy, exper_index, i, k))
            attack_utility.append(attack_response[k].agent.utility)
            defense_utility.append(defense_response[k].agent.utility)

        pickle.dump(defense_utility, open(os.path.join(model_dir, "defender-utility-{}.pickle".format(exper_index)),'wb'))

        # Get the best defense and attack policy
        attack_index = attack_utility.index(max(attack_utility))
        defense_index = defense_utility.index(max(defense_utility))
        attack_policy = attack_response[attack_index].agent.policy
        defense_policy = defense_response[defense_index].agent.policy

        # Delete the models that are not the selected one
        for k in range(N_TRIAL):
            if k != defense_index:
                defender_path = os.path.join(model_dir, "defender-{}-{}-{}".format(exper_index, i, k))
                if os.path.exists(defender_path):
                    import shutil
                    shutil.rmtree(defender_path)
            if k != attack_index:
                attacker_path = os.path.join(model_dir, "attacker-{}-{}-{}".format(exper_index, i, k))
                if os.path.exists(attacker_path):
                    import shutil
                    shutil.rmtree(attacker_path)

        # Update profile    
        payoff, attack_profile, defense_profile = update_profile(model, payoff, attack_profile, defense_profile, attack_policy, defense_policy)

        # Test the terminate condition
        attack_pure_utility = -1*np.dot(payoff[:,i+initial_attack_size][0:(len(payoff[:,i+initial_attack_size])-1)], defense_strategy)
        defense_pure_utility = np.dot(payoff[i+initial_defense_size][0:(len(payoff[i+initial_defense_size])-1)], attack_strategy)

        if -1*utility >= attack_pure_utility and utility >= defense_pure_utility:
            # Save the mixed strategies
            pickle.dump(defense_strategy, open(os.path.join(model_dir, "defender-strategy-{}.pickle".format(exper_index)),'wb'))
            pickle.dump(attack_strategy, open(os.path.join(model_dir, "attacker-strategy-{}.pickle".format(exper_index)),'wb'))
            break
        if i == MAX_ITERATION-1:
            pickle.dump(defense_strategy, open(os.path.join(model_dir, "defender-strategy-{}.pickle".format(exper_index)),'wb'))
            pickle.dump(attack_strategy, open(os.path.join(model_dir, "attacker-strategy-{}.pickle".format(exper_index)),'wb'))
    return payoff_record[-1]

def test_mixed_NE():
    """
    Test find_mixed_NE with the Matching Pennies game and Rock-Paper-Scissors on page 58 of Multiagent Systems.
    The mixed strategy at NE should be 0.5 for each player
    """
    #payoff = np.array([[1,-1],[-1,1]]) # Matching Pennies
    payoff = np.array([[0,-1,1],[1,0,-1],[-1,1,0]]) # Rock, Paper, Scissors
    attack_strategy, defense_strategy, utility = find_mixed_NE(payoff)
    print(attack_strategy, defense_strategy)

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s / %(levelname)s: %(message)s', level=logging.DEBUG)
    logging.info("Experiment starts.")
    if len(sys.argv) < 5:
        print("python double_oracle.py [dataset] [def_budget] [adv_budget] [n_experiment]")
        print("  dataset: 'suricata', 'fraud', 'snort', 'alert.json', 'alert_json.txt', or path to alert file")
        sys.exit(1)

    model_name = sys.argv[1]
    def_budget = float(sys.argv[2])
    adv_budget = float(sys.argv[3])
    n_experiment = int(sys.argv[4])

    # Check if model_name is a path to alert.json/alert_json.txt file
    # Accept both .json and .txt extensions, or any existing file path
    is_alert_file = (model_name.endswith('.json') or 
                     model_name.endswith('.txt') or 
                     'alert_json' in model_name.lower() or
                     (os.path.exists(model_name) and model_name not in ['suricata', 'fraud', 'snort', 'realtime']))
    
    # Determine model_name_for_files (used in directory structure)
    if model_name == 'realtime':
        # Use predefined real-time model with all 10 attack types
        from test import test_model_realtime
        model = test_model_realtime(def_budget, adv_budget)
        model_name_for_files = 'realtime'
        logging.info("Using predefined real-time model with 10 attack types")
    elif is_alert_file:
        # Use alert.json/alert_json.txt file
        alert_file_path = model_name
        if not os.path.exists(alert_file_path):
            # Try default location
            default_path = os.path.expandvars("$VIRTUAL_ENV/snort3/var/log/snort/alert_json.txt")
            if os.path.exists(default_path):
                alert_file_path = default_path
            else:
                print(f"[ERROR] Alert file not found: {alert_file_path}")
                print(f"[ERROR] Also tried default location: {default_path}")
                sys.exit(1)
        logging.info(f"Loading model from alert file: {alert_file_path}")
        model = test_model_from_alerts(alert_file_path, def_budget, adv_budget)
        model_name_for_files = 'alert_json'
    elif model_name == 'suricata':
        model = test_model_suricata(def_budget, adv_budget)
        model_name_for_files = model_name
    elif model_name == 'fraud':
        model = test_model_fraud(def_budget, adv_budget)
        model_name_for_files = model_name
    elif model_name == 'snort':
        model = test_model_snort(def_budget, adv_budget)
        model_name_for_files = model_name
    else:
        print(f"[ERROR] Unknown dataset: {model_name}")
        print("Supported datasets: 'suricata', 'fraud', 'snort', 'realtime', 'alert_json.txt', or path to alert file")
        sys.exit(1)
    
    # Create the directory structure for saving model files
    model_dir = "../model/converge/{}_{}_{}_do".format(model_name_for_files, int(def_budget), int(adv_budget))
    os.makedirs(model_dir, exist_ok=True)
    
    # Set the base directory for ddpg.py to use (ddpg is already imported at top)
    ddpg.MODEL_BASE_DIR = model_dir

    def evaluation(exper_index):
        random_seed = exper_index
        np.random.seed(random_seed)
        tf.set_random_seed(random_seed)
        do_utility = double_oracle(model, exper_index, model_dir)
        return do_utility

    cores = multiprocessing.cpu_count()
    #cores = 1	
    pool = multiprocessing.Pool(processes=cores)
    utilities = []
    for do_utility in pool.imap(evaluation, range(n_experiment)):
        utilities.append(do_utility)    
    logging.info("The utility of the agent:")
    print(utilities)

