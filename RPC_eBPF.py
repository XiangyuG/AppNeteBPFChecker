from z3 import *

N = 2 # Number of packets
# Input variables
fixed_random = BitVec('fixed_random', 16)
decision_record = BitVec('decision_record', 1)  # stored state in eBPF

def AppNet(fixed_random):
    pkt_process_decision = If(fixed_random > 5, BitVecVal(1, 1), BitVecVal(0, 1))
    return pkt_process_decision

def eBPF(ID, fixed_random, decision_record):
    if ID == 0:
        pkt_process_decision = If(fixed_random > 5, BitVecVal(1, 1), BitVecVal(0, 1))
    else:
        pkt_process_decision = decision_record
    return pkt_process_decision


# Setup solver to check equivalence
s = Solver()

eBPF_decision_exprs = []
for i in range(N):
    eBPF_decision_exprs.append(BitVec(f'eBPF_process_decision{i}', 1))

AppNet_process_decision = BitVec('eBPF_process_decision', 1)

AppNet_process_decision = AppNet(fixed_random)

for i in range(N):
    eBPF_decision_exprs[i] = eBPF(i, fixed_random, decision_record)
    decision_record = eBPF_decision_exprs[i]
# eBPF_process_decision0 = eBPF(0, fixed_random, decision_record)
# eBPF_process_decision1 = eBPF(1, fixed_random, eBPF_process_decision0)

constraints = []
for i in range(N):
    constraints.append(AppNet_process_decision != eBPF_decision_exprs[i])

s.add(Or(constraints))

if s.check() == sat:
    model = s.model()
    # Return counter example's value, including the input bitstream + all packet fields' initial values
    print(model)
    print("Counter example found:")
else:
    print("Same behavior for all inputs.")