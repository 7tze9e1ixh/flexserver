import pandas as pd

output = open("result_avg.txt", "w")

csv_file = "flexserver.csv"
df = pd.read_csv(csv_file)
host_mean = round(df.iloc[150:251, 0].mean(), 4)
snic_mean = round(df.iloc[150:251, 1].mean(), 4)
total_mean = round(host_mean + snic_mean, 4)

output.write(f"host:  {host_mean}\n")
output.write(f"snic:  {snic_mean}\n")
output.write(f"total: {total_mean}\n")
