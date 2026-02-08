#!/usr/bin/env python3
"""Debug script to identify why rewards_per_attack.csv has all zeros."""

import sys
sys.path.insert(0, '/home/vikash/ddpg_workspace/ddpg_AlertPrioritization/ddpg/ddpg_mqtt_125/src')

from config import config  
from model import Model
from test import *
from listutils import *
import numpy as np

# Create a simple snort model
model = test_model_snort(def_budget=1000.0, adv_budget=500.0)
print(f"Model created: {len(model.attack_types)} attack types, {len(model.alert_types)} alert types")
print(f"Horizon: {model.horizon}")
print(f"Attack costs: {[a.cost for a in model.attack_types]}")
print(f"Attack losses: {[a.loss for a in model.attack_types]}")

# Create initial state
state = Model.State(model)
print(f"\nInitial state:")
print(f"  M (undetected attacks): {state.M}")
print(f"  U (cumulative loss): {state.U}")

# Simulate some attacks being mounted
print(f"\n--- Simulating first step with test_attack_action ---")

# Get attack action from test policy
attack_action = test_attack_action(model, state)
print(f"Attack action probabilities: {attack_action}")

# Get defense action (uniform)
defense_action = test_defense_newest(model, state)
print(f"Defense action (first 10 elements): {defense_action[0][:10]}")

# Make feasible
alpha = model.make_attack_feasible(attack_action)
print(f"Feasible attack probabilities: {alpha}")

delta = model.make_investigation_feasible(state.N, defense_action)
print(f"Feasible defense action shape: {len(delta)} x {len(delta[0]) if delta else 0}")

# Compute next state
next_state = model.next_state('old', state, delta, alpha)
print(f"\nAfter step 1:")
print(f"  M (undetected attacks): {next_state.M}")
print(f"  U (cumulative loss): {next_state.U}")

loss = -1.0 * (next_state.U - state.U)
print(f"  Loss: {loss}")
print(f"  Reward (should be > 0 if loss < 0): {-1.0 * loss}")

# Continue for a few more steps
state = next_state
for step in range(2, 5):
    next_state = model.next_state('old', state, delta, alpha)
    loss = -1.0 * (next_state.U - state.U)
    print(f"\nAfter step {step}:")
    print(f"  M: {next_state.M}")
    print(f"  U: {next_state.U}")
    print(f"  Loss: {loss}")
    state = next_state
