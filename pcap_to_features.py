import numpy as np
import pandas as pd
import sys,os,re

#read input: 
# 1: device name
# 2: window duration
# 3: input csv 
# 4: output file
# 5: DNS txt file
dev_name = sys.argv[1]
win_duration = float(sys.argv[2])
input_file = sys.argv[3]
output_file = sys.argv[4]
dns_file = sys.argv[5]

#take the file dns-queries and return an ip-domain and a domain-ip object (k-v)
#the dev is the mac
def parse_dns_queries(filename):
    f = open(filename,"r")
    ips_domain = {}
    for row in f:
        if " " not in row:
            continue
        domain, ips = row[:-1].split(" ")
        ips = ips.split(",")
        for ip in ips:
            ips_domain[ip] = domain
    return ips_domain
    
def preprocess_data(data,dev,ips_doms=None):
    #set the value for protocols from the frame.protocols field
    data["proto"]="UNKNOWN" #set default to UNKNOWN
    data.loc[data["frame_protocols"]=="eth:ethertype:ip:udp:data","proto"]="UDP"
    data.loc[data["frame_protocols"]=="eth:ethertype:ip:tcp","proto"]="TCP"
    data.loc[data["frame_protocols"].str.contains("eth:ethertype:ip:tcp:tls"),"proto"]="TLS"
    data.loc[data["frame_protocols"]=="eth:ethertype:ip:tcp:data","proto"]="TCP"
    
    #data.loc[data["frame_protocols"]=="eth:ethertype:arp","proto"]="ARP"
    #data.loc[data["frame_protocols"]=="eth:ethertype:ip:udp:dns","proto"]="DNS"
    #data.loc[data["frame_protocols"]=="eth:ethertype:ip:udp:dhcp","proto"]="DHCP"
    #data.loc[data["frame_protocols"]=="eth:ethertype:ip:udp:ntp","proto"]="NTP"
    #data.loc[data["frame_protocols"]=="eth:ethertype:ip:icmp:data","proto"]="ICMP"
    #data.loc[data["frame_protocols"]=="eth:ethertype:ip","proto"]="IP"
    #data.loc[data["frame_protocols"].str.contains('eth:ethertype:ip:icmp:ip'),"proto"]="UNREACHABLE"

    #take only TCP (and TLS) and UDP
    #data = data.loc[(data["proto"]=="TCP") | (data["proto"]=="UDP") | (data["proto"]=="TLS")]
    data = data.loc[~(data["proto"]=="UNKNOWN")]
    
    #return if empty datasets
    if data.shape[0]==0:
        return data
    
    #remove broadcast 
    data = data.loc[(data["ip_src"]==dev["IP"]) | (data["ip_dst"]==dev["IP"])] #remove broadcast and weird data
    data = data.loc[data["ip_dst"]!= "255.255.255.255"] #skip broadcast
    
    #drop LAN traffic (take the netmask first)
    dev_ip_bytes = dev["IP"].split(".")
    starts_with = f"{dev_ip_bytes[0]}.{dev_ip_bytes[1]}." #13.10.xxxx
    data = data.loc[((data["ip_src"]!=dev["IP"]) & ~(data["ip_src"].str.startswith(starts_with)))|
                    ((data["ip_dst"]!=dev["IP"]) & ~(data["ip_dst"].str.startswith(starts_with)))]
    
    
    #assign the domain from IPs (take domain from dns queries)
    if ips_doms is None:
        ips_doms = parse_dns_queries(dns_file)
    data.loc[data["ip_src"]==dev["IP"],"domain"] = data["ip_dst"].apply(lambda x: ips_doms.get(x,x))
    data.loc[data["ip_dst"]==dev["IP"],"domain"] = data["ip_src"].apply(lambda x: ips_doms.get(x,x))

    #assign src_port and dst_port
    data.loc[data["proto"]=="UDP","src_port"] = data.loc[data["proto"]=="UDP","udp_srcport"]
    data.loc[data["proto"]=="UDP","dst_port"] = data.loc[data["proto"]=="UDP","udp_dstport"]
    data.loc[(data["proto"]=="TCP")|(data["proto"]=="TLS"),"src_port"] = data.loc[(data["proto"]=="TCP")|(data["proto"]=="TLS"),"tcp_srcport"]
    data.loc[(data["proto"]=="TCP")|(data["proto"]=="TLS"),"dst_port"] = data.loc[(data["proto"]=="TCP")|(data["proto"]=="TLS"),"tcp_dstport"]
    
    #drop all except TCP and UDP
    data = data.loc[(data["proto"]=="TCP")|(data["proto"]=="UDP")|(data["proto"]=="TLS")]
    
    #drop unuseful columns
    data.drop(["udp_srcport","udp_dstport","tcp_srcport","tcp_dstport","frame_protocols","ip_len"],inplace=True,axis=1,errors="ignore")
    data["frame_time_epoch"] = data["frame_time_epoch"].astype(float)
    data["frame_len"] = data["frame_len"].astype(float)
    
    return data

    
#return one df per domain
def group_by_domain(df):
    column="domain"
    return {d : df.loc[df[column]==d].reset_index() for d in df[column].unique()}
#return one df per remote_ip
def group_by_ip(df,dev):
    ip_list = list(set(df.loc[df["ip_src"]!=dev["IP"],"ip_src"].to_list()+ df.loc[df["ip_dst"]!=dev["IP"],"ip_dst"].to_list()))
    return {ip : df.loc[(df["ip_src"]==ip)|(df["ip_dst"]==ip)].reset_index() for ip in ip_list}
    
# given a df of packets, extracts iats and size features
def packets_to_ftrs(packets):
    # (frame_size) ftrs: ["cnt","sum","mean","mdn","std","min","max","q1","q2","q3"]
    if packets.shape[0]==0:
        return [0 for i in range(17)]
    
    frame_lens = packets["frame_len"].to_numpy()
    frame_ftrs = [len(frame_lens),np.sum(frame_lens),np.mean(frame_lens),np.median(frame_lens),np.std(frame_lens),np.max(frame_lens),np.min(frame_lens)] + np.quantile(frame_lens, q=[0.25, 0.5, 0.75]).tolist()

    #iats ftrs:  ["mean","std","min","max","q1","q2","q3"]
    times = packets["frame_time_epoch"].to_numpy()
    if len(times)<2:
        iats_ftrs = [0 for i in range(7)]
    else:
        iats = (np.array(times[1:],dtype=np.float64) - np.array(times[:-1],dtype=np.float64))
        iats_ftrs = [np.mean(iats),np.std(iats),np.min(iats),np.max(iats)] + np.quantile(iats, q=[0.25, 0.5, 0.75]).tolist()    
    
    return frame_ftrs + iats_ftrs

#compute the additional features (e.g. tcp/udp rate, ul/dl rate etc)
def get_extra_ftrs(df):
    #tcp over udp rates
    try:
        tcp_udp_pkt = (df[(df["proto"]=="TCP")|(df["proto"]=="TLS")].shape[0]) / (df[df["proto"]=="UDP"].shape[0])
        tcp_udp_byte = (df.loc[(df["proto"]=="TCP")|(df["proto"]=="TLS"),"frame_len"].sum()) / (df.loc[df["proto"]=="UDP","frame_len"].sum())
    except:
        tcp_udp_pkt,tcp_udp_byte = [0,0]
    
    #tls over tcp rates
    try:
        tls_tcp_pkt = (df[df["proto"]=="TLS"].shape[0]) / (df[df["proto"]=="TCP"].shape[0])
        tls_tcp_byte = (df.loc[df["proto"]=="TLS","frame_len"].sum()) / (df.loc[df["proto"]=="TCP","frame_len"].sum())
    except:
        tls_tcp_pkt,tls_tcp_byte = [0,0]
        
    #ul over dl rates
    try:
        ul_dl_pkt = (df[df["direction"]=="UL"].shape[0]) / (df[df["direction"]=="DL"].shape[0])
        ul_dl_byte = (df.loc[df["direction"]=="UL","frame_len"].sum()) / (df.loc[df["direction"]=="DL","frame_len"].sum())
    except:
        ul_dl_pkt,ul_dl_byte = [0,0]
        
    #Number of ports
    #TCP and TLS
    tcp_local_ports = list(df.loc[((df["proto"]=="TCP")|(df["proto"]=="TLS")) & (df["direction"]=="UL"),"src_port"])
    tcp_local_ports = tcp_local_ports + list(df.loc[((df["proto"]=="TCP")|(df["proto"]=="TLS")) & (df["direction"]=="DL"),"dst_port"])
    tcp_local_ports = len(set(tcp_local_ports))
                        
    tcp_remote_ports = list(df.loc[((df["proto"]=="TCP")|(df["proto"]=="TLS")) & (df["direction"]=="UL"),"dst_port"])
    tcp_remote_ports = tcp_remote_ports + list(df.loc[((df["proto"]=="TCP")|(df["proto"]=="TLS")) & (df["direction"]=="DL"),"src_port"])
    tcp_remote_ports = len(set(tcp_remote_ports))
    
    #UDP
    udp_local_ports = list(df.loc[(df["proto"]=="UDP") & (df["direction"]=="UL"),"src_port"])
    udp_local_ports = udp_local_ports + list(df.loc[(df["proto"]=="UDP") & (df["direction"]=="DL"),"dst_port"])
    udp_local_ports = len(set(udp_local_ports))
    
    udp_remote_ports = list(df.loc[(df["proto"]=="UDP") & (df["direction"]=="UL"),"dst_port"])
    udp_remote_ports = udp_remote_ports + list(df.loc[(df["proto"]=="UDP") & (df["direction"]=="DL"),"src_port"])
    udp_remote_ports = len(set(udp_remote_ports))
    
    def flow_str(row):
        flow_string = f"{row['src_port']}:{row['dst_port']}" if row["direction"] =="UL" else f"{row['dst_port']}:{row['src_port']}"
        return flow_string
    
    #count flows
    df["flow_pair"] = df[df.columns].apply(lambda x: flow_str(x), axis=1)
    tcp_flows = len(df.loc[(df["proto"]=="TCP")|(df["proto"]=="TLS"),"flow_pair"].unique())
    udp_flows = len(df.loc[df["proto"]=="UDP","flow_pair"].unique())
    
    #build extra ftrs list
    extra_ftrs = [tcp_udp_pkt,tcp_udp_byte,
                  tls_tcp_pkt,tls_tcp_byte,
                  ul_dl_pkt,ul_dl_byte,
                  tcp_local_ports,tcp_remote_ports,tcp_flows,
                  udp_local_ports,udp_remote_ports,udp_flows]
    
    return extra_ftrs

#group by windowed timestamp and build the final dataframe
def extract_windowed_ftrs(df,dev,win_len,verbose=True):
    #assign the time window
    startTime = df["frame_time_epoch"].min()
    df["time_window"] = df["frame_time_epoch"].apply(lambda x: startTime + int((x-startTime)/win_len)*win_len)
    
    #assign the domain
    domain = df["domain"].tolist()[0]
    
    #assign the direction as uplink or downlink
    df.loc[df["ip_src"]==dev["IP"],"direction"]="UL"
    df.loc[df["ip_dst"]==dev["IP"],"direction"]="DL"
    
    base_ftrs = ["num_pkt","tot_bytes","mean_size","mdn_size","std_size","min_size","max_size","q1_size","q2_size","q3_size",
                "mean_iat","std_iat","min_iat","max_iat","q1_iat","q2_iat","q3_iat"]
    suffixes = ["_tcp_ul","_tcp_dl","_tcp","_tls_ul","_tls_dl","_tls","_udp_ul","_udp_dl","_udp","_ul","_dl",""]
    extra_ftrs = ["tcp_udp_pkt_rate","tcp_udp_byte_rate","tls_tcp_pkt_rate","tls_tcp_byte_rate","ul_dl_pck_rate","ul_dl_byte_rate",
                 "tcp_local_ports","tcp_remote_ports","tcp_flows","udp_local_ports","udp_remote_ports","udp_flows"]
    col_names = ["time_window"]+[f"{base}{suffix}" for suffix in suffixes for base in base_ftrs] + extra_ftrs + ["domain"]
    df_list = []
    
    #group by and repeat for each time window
    by_window = df.groupby('time_window')
    #for each time window compute the features
    for window, group in by_window:
        #compute all features
        feature_values = [window] + \
        packets_to_ftrs(group[((group["proto"]=="TCP")|(group["proto"]=="TLS"))&(group["direction"]=="UL")]) + \
        packets_to_ftrs(group[((group["proto"]=="TCP")|(group["proto"]=="TLS"))&(group["direction"]=="DL")]) + \
        packets_to_ftrs(group[((group["proto"]=="TCP")|(group["proto"]=="TLS"))]) + \
        packets_to_ftrs(group[(group["proto"]=="TLS")&(group["direction"]=="UL")]) + \
        packets_to_ftrs(group[(group["proto"]=="TLS")&(group["direction"]=="DL")]) + \
        packets_to_ftrs(group[(group["proto"]=="TLS")]) + \
        packets_to_ftrs(group[(group["proto"]=="UDP")&(group["direction"]=="UL")]) + \
        packets_to_ftrs(group[(group["proto"]=="UDP")&(group["direction"]=="DL")]) + \
        packets_to_ftrs(group[(group["proto"]=="UDP")]) + \
        packets_to_ftrs(group[(group["direction"]=="UL")]) + \
        packets_to_ftrs(group[(group["direction"]=="DL")]) + \
        packets_to_ftrs(group) + \
        get_extra_ftrs(group) + [domain]
        
        df_list.append(feature_values)

    return pd.DataFrame(df_list,columns = col_names)

#group the dataset by time window, for each ip or domain
def df_to_windowed(df,dev,win_len,by_ip=True,verbose=False):
    windowed_df = None
    
    if(by_ip): #consider each ip of domains separately or not
        dfs_by_domain = group_by_ip(df,dev)
    else:
        dfs_by_domain = group_by_domain(df)
    
    for dom_ip,dom_df in dfs_by_domain.items():
        domain = dom_df["domain"].tolist()[0]
        label = "Required"
        
        #check if the domain is ok or not
        for bad_domain in dev["bad_dests"]:
            # Use re.match to check if the domain matches the key with wildcards
            if re.match("^" + re.escape(bad_domain).replace("\\*", ".*") + "$", domain):
                label = "Non-Required"
        #get the features for each domain
        dom_windowed_df = extract_windowed_ftrs(dom_df,dev,win_len,verbose=verbose)
        
        #assign the remote ip label, which otherwise gets lost
        if(by_ip):
            dom_windowed_df["server_ip"]=dom_ip #track also the ip, not only domain
        dom_windowed_df["Label"] = label
        
        #concat to global df
        windowed_df = dom_windowed_df if windowed_df is None else pd.concat([windowed_df,dom_windowed_df],ignore_index=True)
    
    return windowed_df




#other parameters
moniotr_dir="/opt/moniotr" #moniotr directory
by_ip=True

#read ip for device from moniotr
f=open(f"{moniotr_dir}/traffic/by-name/{dev_name}/ip.txt","r")
dev_ip = f.readline().strip()
f.close()
#read bad_dests for device, if any
bad_dests = []
try:
    with open(f"{moniotr_dir}/traffic/tagged/{dev_name}/non-essential","r") as f:
        for line in f.readlines():
            if not line.strip().startswith("#") and line.strip()!= "":
                bad_dests.append(line.strip())
except FileNotFoundError as e:
    print("No bad_dests provided, labelling all as good")
    

dev = {"IP":dev_ip,"bad_dests":bad_dests}

#convert the csv into windowed features
columns = ["frame_time_epoch","frame_len","frame_protocols","eth_src","eth_dst","ip_src","ip_dst","ip_proto","ip_len","tcp_srcport","tcp_dstport","udp_srcport","udp_dstport","tcp_flags"]

ips_doms = parse_dns_queries(dns_file)
df = pd.read_csv(input_file,names=columns,index_col=False)
df = preprocess_data(df,dev,ips_doms)
df = df_to_windowed(df,dev,win_duration,by_ip=by_ip)

os.makedirs(os.path.dirname(output_file),exist_ok=True)
df.to_csv(output_file,index=None)
