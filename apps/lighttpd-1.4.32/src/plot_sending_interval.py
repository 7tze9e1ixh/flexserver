import csv
import math
import matplotlib.pyplot as plt

LAST_SENT_TS_GRANURALITY=10 
LAST_SENT_TS_DURATION=1000
LAST_SENT_TS_SIZE=(LAST_SENT_TS_DURATION // LAST_SENT_TS_GRANURALITY)

fn = "last_sent_ts.csv"

x_axis = [LAST_SENT_TS_GRANURALITY * i for i in range(LAST_SENT_TS_SIZE + 1)]
y_axis = [0 for _ in range(LAST_SENT_TS_SIZE + 1)]
cnt = 0

with open(fn) as f_csv :
    csv_rdr = csv.reader(f_csv)
    for row in csv_rdr :
        last_sent_ts = list(map(int, row))
        
       # print(last_sent_ts)
        
        if last_sent_ts[0] == 0 : continue
                
        for i in range(LAST_SENT_TS_SIZE) :
         #   print(i)
            y_axis[i] += last_sent_ts[i]
        
    cnt += 1
    
for i in range(LAST_SENT_TS_SIZE) :
    y_axis[i] //= cnt
    
plt.xlabel("ms")
plt.ylabel("# stream")
plt.yscale('log', base=10)
plt.plot(x_axis, y_axis)
plt.savefig('log/Latency/FixedWnd/status.png')
