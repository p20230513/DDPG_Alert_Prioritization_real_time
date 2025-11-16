#!/usr/bin/env python3
"""
evaluate_ddpg_live.py
-------------------------------------
Real-time DDPG Alert Prioritization with live Snort++ alerts.
Integrates:
  - Snort3 live alerts (JSON format)
  - simulate_model.py alert-type mapping
  - Real-time online training of DDPG agent
"""

import os
import sys
import json
import time
import argparse
from collections import deque, defaultdict

# --- Ensure imports work ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from simulate_model import get_alert_type_index, alert_types

# ==============================================================
# Utility Classes
# ==============================================================

class ReplayBuffer:
    """Simple experience replay buffer for online RL training."""
    def __init__(self, capacity=20000):
        self.capacity = capacity
        self.buffer = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size):
        import random
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))
        s, a, r, ns, d = zip(*batch)
        return list(s), list(a), list(r), list(ns), list(d)

    def __len__(self):
        return len(self.buffer)


# ==============================================================
# File tailing for Snort live alerts
# ==============================================================

def tail_json_lines(path, poll_interval=0.1):
    """Tail a newline-delimited JSON alert file and yield parsed dicts."""
    print(f"[INFO] Watching alert file: {path}")
    while not os.path.exists(path):
        print(f"[WAIT] Waiting for {path} to appear...")
        time.sleep(1)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ==============================================================
# State Encoding (adapt to your model)
# ==============================================================
def encode_alert_for_agent(alert_json):
    """
    Convert Snort JSON alert (dict) into a numeric state vector.
    """
    # Extract message / signature text
    msg = ""
    if "alert" in alert_json and isinstance(alert_json["alert"], dict):
        msg = alert_json["alert"].get("signature", "") or alert_json["alert"].get("msg", "")
    if not msg:
        msg = alert_json.get("event_type", "unknown")

    # Map to alert type
    idx = get_alert_type_index(msg)
    one_hot = [0.0] * len(alert_types)
    if 0 <= idx < len(one_hot):
        one_hot[idx] = 1.0

    # Extract priority
    priority = float(alert_json.get("alert", {}).get("priority", 0) or 0)

    # Optional numeric state (one-hot + priority)
    import numpy as np
    return np.array(one_hot + [priority], dtype=float)

# ==============================================================
# Training utility
# ==============================================================

def train_step(agent, replay_buffer, batch_size=64, train_iters=1):
    """Sample from buffer and call agent.update()"""
    if len(replay_buffer) < batch_size:
        return
    for _ in range(train_iters):
        s, a, r, ns, d = replay_buffer.sample(batch_size)
        if hasattr(agent, "update"):
            agent.update(s, a, r, ns, d)


# ==============================================================
# Main live loop
# ==============================================================

def run_live(agent,
             alert_file,
             replay_buffer,
             steps_per_train=50,
             max_steps=None,
             batch_size=64,
             train_iters=1):
    """Main loop to process live Snort alerts and train agent online."""
    step = 0
    stats = defaultdict(int)

    print(f"[LIVE] Monitoring Snort alerts from: {alert_file}")

    for alert_json in tail_json_lines(alert_file):
        step += 1
        msg = alert_json.get("alert", {}).get("signature", "")
        
        if step % 20 == 0:
        print(f"[DEBUG] Raw alert: {json.dumps(alert_json)[:120]}")
        print(f"[DEBUG] Parsed msg={msg}, priority={alert_json.get('alert', {}).get('priority')}")

        idx = get_alert_type_index(msg)
        src = alert_json.get("src_ip")
        dst = alert_json.get("dest_ip")
        priority = alert_json.get("alert", {}).get("priority", 0)

        # Encode for DDPG agent
        state = encode_alert_for_agent(alert_json)

        # Select action (priority decision)
        if hasattr(agent, "select_action"):
            action = agent.select_action(state)
        else:
            action = 0  # fallback

        # Reward (customize to your design)
        reward = 1.0 if int(priority) > 1 else 0.1

        next_state = state
        done = False

        # Store experience
        if hasattr(agent, "store_transition"):
            agent.store_transition(state, action, reward, next_state, done)
        else:
            replay_buffer.push(state, action, reward, next_state, done)

        # Stats & logging
        stats[msg] += 1
        print(f"[{step}] {msg} | idx={idx} | act={action:.2f} | rew={reward:.2f} | src={src}->{dst}")

        # Training
        if step % steps_per_train == 0:
            print(f"[TRAIN] Updating agent on {len(replay_buffer)} samples ...")
            train_step(agent, replay_buffer, batch_size, train_iters)
            if hasattr(agent, "save"):
                agent.save()
                print("[SAVE] Model checkpointed.")

        if max_steps and step >= max_steps:
            break


# ==============================================================
# Entry Point
# ==============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run DDPG alert prioritization on live Snort++ alerts")
    parser.add_argument("--alert-file",
                        default=os.path.expandvars("$VIRTUAL_ENV/snort3/var/log/snort/alert_json.txt"),
                        help="Path to Snort alert_json.txt file")
    parser.add_argument("--steps-per-train", type=int, default=50)
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--train-iters", type=int, default=1)
    args = parser.parse_args()

    # TODO: Import or create your DDPG agent here
    try:
        from ddpg_agent import Agent
        agent = Agent()
        agent.load()  # load pretrained weights if exists
    except Exception:
        print("[WARN] ddpg_agent not found. Using dummy agent for testing.")
        class DummyAgent:
            def select_action(self, s): return 0
            def store_transition(self, *a, **kw): pass
            def update(self, *a, **kw): pass
            def save(self): pass
        agent = DummyAgent()

    buffer = ReplayBuffer(20000)

    run_live(agent,
             alert_file=args.alert_file,
             replay_buffer=buffer,
             steps_per_train=args.steps_per_train,
             max_steps=args.max_steps,
             batch_size=args.batch_size,
             train_iters=args.train_iters)

