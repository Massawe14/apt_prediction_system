import gymnasium as gym
from gymnasium import spaces
import numpy as np

class APTEnv(gym.Env):
    def __init__(self, X, y_activity, y_stage, max_activity, num_stages):
        super(APTEnv, self).__init__()
        self.X = X
        self.y_activity = y_activity
        self.y_stage = y_stage
        self.current_step = 0
        self.max_steps = len(X) - 1
        
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(X.shape[1], X.shape[2]), dtype=np.float32
        )
        self.action_space = spaces.MultiDiscrete([max_activity + 1, num_stages])
        
        self.pred_activity_history = []
        self.true_activity_history = []
        self.pred_stage_history = []
        self.true_stage_history = []

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        self.pred_activity_history.clear()
        self.true_activity_history.clear()
        self.pred_stage_history.clear()
        self.true_stage_history.clear()
        return self.X[self.current_step], {}

    def step(self, action):
        activity_pred, stage_pred = action
        true_activity = self.y_activity[self.current_step]
        true_stage = self.y_stage[self.current_step]

        activity_weights = {
            'Malware Download': 5, 'Backdoor': 5, 'CSRF': 4, 'Command Injection': 4,
            'SQL Injection': 3, 'Account Bruteforce': 2, 'Account Discovery': 2,
            'Web Vulnerability Scan': 1, 'Network Scan': 1, 'Directory Bruteforce': 1,
            'BENIGN': 0.5
        }
        stage_weights = {
            'Data Exfiltration': 5, 'Lateral Movement': 4, 'Establish Foothold': 3,
            'Reconnaissance': 2, 'BENIGN': 0.5
        }

        reward = 0
        if activity_pred == true_activity:
            reward += activity_weights.get(true_activity, 1)
        else:
            reward -= activity_weights.get(true_activity, 1) / 2
        if stage_pred == true_stage:
            reward += stage_weights.get(true_stage, 1)
        else:
            reward -= stage_weights.get(true_stage, 1) / 2

        self.pred_activity_history.append(activity_pred)
        self.true_activity_history.append(true_activity)
        self.pred_stage_history.append(stage_pred)
        self.true_stage_history.append(true_stage)

        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        truncated = False
        obs = self.X[self.current_step] if not terminated else np.zeros_like(self.X[0])
        return obs, reward, terminated, truncated, {}
    