import matplotlib.pyplot as plt
from collections import Counter

with open("alerts.log") as f:
    alerts = f.read()

types = ["SQL Injection", "XSS", "Brute Force", "Port Scan", "ICMP Flood"]
counts = [alerts.count(t) for t in types]

plt.bar(types, counts)
plt.title("NIDS - Detected Attacks")
plt.xticks(rotation=20)
plt.savefig("attack_graph.png")
print("Graph saved as attack_graph.png")
