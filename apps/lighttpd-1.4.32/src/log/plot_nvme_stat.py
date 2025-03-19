import csv
import math
import matplotlib.pyplot as plt
import time

NUM_NVMES=4
ALGINED=50000
RATIO_MONOTORING_RANGE=1000

prefix="nvme_stat/"
now = time.strftime("%m-%d-%H:%M:%S")
nrow = 0
max_lat = 0
nrow_max_lat = 0

max_numIOPendings = 0

latency = [[] for _ in range(NUM_NVMES)]
numIOPendings = [[] for _ in range(NUM_NVMES)]
gbps = [[] for _ in range(NUM_NVMES)]
rate = [[] for _ in range(NUM_NVMES)]

numIOPendings_latency = [[] for _ in range(NUM_NVMES)]

with open("nvme_stat.csv") as f_csv :
    csv_rdr = csv.reader(f_csv)
    for row in csv_rdr :
        row_list = list(map(float, row))
       # print(row)
        for i in range(NUM_NVMES) :
            if row_list[NUM_NVMES + i] >= max_lat :
                if row_list[NUM_NVMES + i] != math.inf : 
                    max_lat = row_list[NUM_NVMES + i]
                    nrow_max_lat = nrow
                    
            latency[i].append(row_list[NUM_NVMES + i])
        nrow += 1
        
        for i in range(NUM_NVMES) :
            numIOPendings[i].append(row_list[2*NUM_NVMES + i])
            if row_list[2 * NUM_NVMES + i] >= max_numIOPendings :
                max_numIOPendings = row_list[2 * NUM_NVMES + i]
            
        for i in range(NUM_NVMES) :
            gbps[i].append(row_list[i])
            
        for i in range(NUM_NVMES) :
            n = row_list[2*NUM_NVMES+i]
            if row_list[NUM_NVMES + i] != math.inf :
                t = row_list[NUM_NVMES + i]
            else :
                t = 0
            numIOPendings_latency[i].append((n, t))
            
        for i in range(NUM_NVMES) :
            rate[i].append(row_list[3 * NUM_NVMES + i])
            

t = [i for i in range(len(latency[0]))]

print(max_lat, nrow_max_lat)

ylimit = (max_lat // ALGINED + 1) * ALGINED

plt.figure(1)

for i in range(1, NUM_NVMES + 1) :
    plt.subplot(2, 2, i)
    plt.plot(t, latency[i-1], 'bo', markersize=0.1)
    plt.xlabel('Time(ms)')
    plt.ylabel('Latency(us)')
    #plt.ylim([0, max_lat])
    plt.title('nvme' + str(i-1) + " latency")
    plt.ylim([0, ylimit])

plt.tight_layout()
output_filename = prefix + now + "-latency.png"
plt.savefig(output_filename)

plt.figure(2)

for i in range(1, NUM_NVMES + 1) :
    plt.subplot(2, 2, i)
    plt.plot(t, numIOPendings[i-1], 'ro', markersize=0.1)
    plt.xlabel('Time(ms)')
    plt.ylabel('# IOPendings')
    plt.title('nvme' + str(i-1) + " numIOPendings")
    
plt.tight_layout()
output_filename = prefix + now + "-io_pendings.png"
plt.savefig(output_filename)

plt.figure(3)
for i in range(1, NUM_NVMES + 1) :
    plt.subplot(2, 2, i)
    plt.plot(t, gbps[i-1], 'ko', markersize=0.1)
    plt.xlabel('Time(ms)')
   # plt.ylim([0, max_lat])
    plt.ylabel('Gbps')
    plt.title('nvme' + str(i-1) + " Gbps")
    
plt.tight_layout()
output_filename = prefix + now + "-throughput.png"
plt.savefig(output_filename)

xlimit = (max_numIOPendings // 100 + 1) * 100
plt.figure(4)
for i in range(1, NUM_NVMES + 1) :
    plt.subplot(2, 2, i)
    plt.scatter(*zip(*numIOPendings_latency[i-1]), s=1)
    plt.xlabel('# IOPendings')
    plt.ylabel('Latency')
    
    plt.ylim([0, ylimit])
    plt.xlim([0, xlimit])
    plt.title('nvme' + str(i-1) + " # IO Pending - Latency(us)")
    
plt.tight_layout()
output_filename = prefix + now +"-#IOPending-Latency.png"
plt.savefig(output_filename)


plt.figure(5)
for i in range(NUM_NVMES) :
  #  plt.plot(t, rate[i],  'ro', markersize=0.1, label="nvme" + str(i))
    plt.plot(t[nrow_max_lat - RATIO_MONOTORING_RANGE // 2 : nrow_max_lat + RATIO_MONOTORING_RANGE // 2], 
             rate[i][nrow_max_lat - RATIO_MONOTORING_RANGE // 2 : nrow_max_lat + RATIO_MONOTORING_RANGE // 2],  
             'o', markersize=0.5, label="nvme" + str(i))
        
plt.xlabel("Time(ms)")
plt.ylabel("Ratio")
plt.legend()
plt.title("NVME ratio")
output_filename = prefix + now +"-ratio.png"
plt.savefig(output_filename)
