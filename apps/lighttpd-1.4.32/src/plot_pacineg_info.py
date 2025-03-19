import csv
import math
import matplotlib.pyplot as plt

PACING_INT_GRANURALITY=10
PACING_INT_DURATION=1000
PACING_INT_ARR_SIZE=(PACING_INT_DURATION // PACING_INT_GRANURALITY) 

fn="pacing_interval.csv"


x_int = [i for i in range(PACING_INT_ARR_SIZE + 1)]
y_num = [0 for _ in range(PACING_INT_ARR_SIZE + 1)]
cnt = 0

with open(fn) as f_csv :
    csv_rdr = csv.reader(f_csv)
    for row in csv_rdr :
        list_interval = list(map(int, row))

        if sum(list_interval) == 0 : continue

        print(len(list_interval))
        for idx in range(PACING_INT_ARR_SIZE) :
            y_num[idx] += list_interval[idx]
        cnt += 1

for idx in range(PACING_INT_ARR_SIZE) :
    y_num[idx] //= cnt

plt.subplot(2, 1, 1)
plt.xlabel("interval(x 10us)")
plt.ylabel("# paced")
plt.plot(x_int, y_num)
plt.savefig("log/pacing_interval/interval.png")

fn = "pacing_interval_gap.csv"

x_gap = [i for i in range(PACING_INT_ARR_SIZE + 1)]
y_num = [0 for _ in range(PACING_INT_ARR_SIZE + 1)]
cnt = 0

with open(fn) as f_csv :
    csv_rdr = csv.reader(f_csv)
    for row in csv_rdr :
        list_gap = list(map(int, row))

        if sum(list_gap) == 0 : continue

        for idx in range(PACING_INT_ARR_SIZE) :
            x_gap[idx] += list_gap[idx]
        cnt += 1

for idx in range(PACING_INT_ARR_SIZE) :
    y_num[idx] //= cnt

plt.subplot(2, 1, 2)
plt.xlabel("gap(x 10us)")
plt.ylabel("# paced")
plt.plot(x_int, y_num)
plt.savefig("log/pacing_interval/gap.png")

