import csv
import math
import matplotlib.pyplot as plt

NUM_STARVED_REASON=3

reasons = ["RATE_LIMIT", "NO_WND_SPACE", "NO_PKT_BUF"]
n_starved_reasons = [0] * 3
fn = "starved_reason.csv"
cnt = 0

with open(fn) as f_csv :
    csv_rdr = csv.reader(f_csv)
    for row in csv_rdr :
        lst = list(map(int, row))
        #if lst[0] == 0 : continue
        cnt += 1
        for i in range(3) :
            n_starved_reasons[i] += lst[i]

for i in range(3) :
    n_starved_reasons[i] /= cnt

print(n_starved_reasons)
