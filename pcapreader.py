import csv
import pandas as pd
import subprocess
import os
import ipaddress
from os.path import exists
class PcapReader:
    def __init__(self):
        self.__name__ = "PcapReader"
        
    @staticmethod        
    def pcapToDf(filename,RetainCSV=False,Tool="Own"):
        """ Reads a pcap file with tshark, extracts the data in it and outputs it to a csv file.
            It then reads the csv file into a dataframe and deletes the csvFile

            Input: 
                Filename (string): path to pcap file
                
                isLindenhof (string): If the pcap trace is from the Lindenhof tool, 
                                       the SNMP protocol gets fragmented and has to be put back together
        """
        try:
            csvFilename = os.path.splitext(filename)[0] + '.csv'
            print(csvFilename)
            if not exists(csvFilename):
                command = "tshark -r " + filename + " -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len -e _ws.col.Info -E header=y -E separator=/t > " + csvFilename
                if Tool == "linderhof" and ("victim" in csvFilename) or ("reflector" in csvFilename):
                    command = command[:len('tshark')+1] + ' -2 ' + command[len('tshark'):] # If the tool is lindenhoff, we need 2 pass analysis for more info on defragmented IP packets
                subprocess.run(command,shell=True)
            # Read headers
            fields = pd.read_csv(csvFilename, index_col=0, nrows=0).columns.tolist()[0].split('\t')
            df = pd.read_csv(csvFilename,sep='\t',header=0,names=fields,na_values=['None'])
            if not RetainCSV:
                os.remove(csvFilename)
            df.rename(columns = {'frame.number':'FrameNumber','frame.time':'Time','ip.src':'Source','ip.dst':'Destination','tcp.srcport':'TCP Source Port','tcp.dstport':'TCP Destination Port','udp.srcport':'UDP Source Port','udp.dstport':'UDP Destination Port','_ws.col.Protocol':'Protocol','frame.len':'Length','_ws.col.Info':'Info'},inplace = True)
            # Conver time column to correct format
            df.Time = df.Time.apply(lambda x: x.strip(" CEST"))
            df.Time = pd.to_datetime(df["Time"], format='%b %d, %Y %H:%M:%S.%f')
            df.Source = df.Source.fillna('0.0.0.0') # 0.0.0.0 is used to represent missing data (In the case of ARP packets for example)
            df.Destination = df.Destination.fillna('0.0.0.0') # 0.0.0.0 is used to represent missing data (In the case of ARP packets for example)
            df.Source = df.Source.apply(lambda x: ipaddress.ip_address((x)))
            df.Destination = df.Destination.apply(lambda x: ipaddress.ip_address(x))
            df = df.astype({"TCP Source Port": 'Int64', "TCP Destination Port": 'Int64', "UDP Source Port": 'Int64', "UDP Destination Port":'Int64'})
            if Tool == "linderhof" and "snmp" in filename:
                # Hard code the weird packet in reflector file level 5 away
                if "6" in filename and "reflector" in filename:
                    df.at[df[df["FrameNumber"] == 516517].index.to_list()[0],"Protocol"] = "SNMP"
                    df.at[df[df["FrameNumber"] == 516517].index.to_list()[0],"Info"] = "get-response 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.1.4.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.6.0 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.1.8.0 1.3.6.1.2.1.1.9.1.2.1 1.3.6.1.2.1.1.9.1.2.2 1.3.6.1.2.1.1.9.1.2.3 1.3.6.1.2.1.1.9.1.2.4 1.3.6.1.2.1.1.9.1.2.5 1.3.6.1.2.1.1.9.1.2.6 1.3.6.1.2.1.1.9.1.2.7 1.3.6.1.2.1.1.9.1.2.8 1.3.6.1.2.1.1.9.1.2.9 1.3.6.1.2.1.1.9.1.2.10 1.3.6.1.2.1.1.9.1.3.1 1.3.6.1.2.1.1.9.1.3.2 1.3.6.1.2.1.1.9.1.3.3 1.3.6.1.2.1.1.9.1.3.4 1.3.6.1.2.1.1.9.1.3.5 1.3.6.1.2.1.1.9.1.3.6 1.3.6.1.2.1.1.9.1.3.7 1.3.6.1.2.1.1.9.1.3.8 1.3.6.1.2.1.1.9.1.3.9 1.3.6.1.2.1.1.9.1.3.10 1.3.6.1.2.1.1.9.1.4.1 1.3.6.1.2.1.1.9.1.4.2 1.3.6.1.2.1.1.9.1.4.3 1.3.6.1.2.1.1.9.1.4.4 1.3.6.1.2.1.1.9.1.4.5 1.3.6.1.2.1.1.9.1.4.6 1.3.6.1.2.1.1.9.1.4.7 1.3.6.1.2.1.1.9.1.4.8 1.3.6.1.2.1.1.9.1.4.9 1.3.6.1.2.1.1.9.1.4.10 1.3.6.1.2.1.25.1.1.0 1.3.6.1.2.1.25.1.2.0 1.3.6.1.2.1.25.1.3.0 1.3.6.1.2.1.25.1.4.0 1.3.6.1.2.1.25.1.5.0 1.3.6.1.2.1.25.1.6.0 1.3.6.1.2.1.25.1.7.0 1.3.6.1.2.1.25.1.7.0"    
                if "7" in filename and "reflector" in filename:
                    df.at[df[df["FrameNumber"] == 1643749].index.to_list()[0],"Protocol"] = "SNMP"
                    df.at[df[df["FrameNumber"] == 1643749].index.to_list()[0],"Info"] = "get-response 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.1.4.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.6.0 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.1.8.0 1.3.6.1.2.1.1.9.1.2.1 1.3.6.1.2.1.1.9.1.2.2 1.3.6.1.2.1.1.9.1.2.3 1.3.6.1.2.1.1.9.1.2.4 1.3.6.1.2.1.1.9.1.2.5 1.3.6.1.2.1.1.9.1.2.6 1.3.6.1.2.1.1.9.1.2.7 1.3.6.1.2.1.1.9.1.2.8 1.3.6.1.2.1.1.9.1.2.9 1.3.6.1.2.1.1.9.1.2.10 1.3.6.1.2.1.1.9.1.3.1 1.3.6.1.2.1.1.9.1.3.2 1.3.6.1.2.1.1.9.1.3.3 1.3.6.1.2.1.1.9.1.3.4 1.3.6.1.2.1.1.9.1.3.5 1.3.6.1.2.1.1.9.1.3.6 1.3.6.1.2.1.1.9.1.3.7 1.3.6.1.2.1.1.9.1.3.8 1.3.6.1.2.1.1.9.1.3.9 1.3.6.1.2.1.1.9.1.3.10 1.3.6.1.2.1.1.9.1.4.1 1.3.6.1.2.1.1.9.1.4.2 1.3.6.1.2.1.1.9.1.4.3 1.3.6.1.2.1.1.9.1.4.4 1.3.6.1.2.1.1.9.1.4.5 1.3.6.1.2.1.1.9.1.4.6 1.3.6.1.2.1.1.9.1.4.7 1.3.6.1.2.1.1.9.1.4.8 1.3.6.1.2.1.1.9.1.4.9 1.3.6.1.2.1.1.9.1.4.10 1.3.6.1.2.1.25.1.1.0 1.3.6.1.2.1.25.1.2.0 1.3.6.1.2.1.25.1.3.0 1.3.6.1.2.1.25.1.4.0 1.3.6.1.2.1.25.1.5.0 1.3.6.1.2.1.25.1.6.0 1.3.6.1.2.1.25.1.7.0 1.3.6.1.2.1.25.1.7.0"    
                if "8" in filename and "reflector" in filename:
                    df.at[df[df["FrameNumber"] == 274709].index.to_list()[0],"Protocol"] = "SNMP"
                    df.at[df[df["FrameNumber"] == 274709].index.to_list()[0],"Info"] = "get-response 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.1.4.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.6.0 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.1.8.0 1.3.6.1.2.1.1.9.1.2.1 1.3.6.1.2.1.1.9.1.2.2 1.3.6.1.2.1.1.9.1.2.3 1.3.6.1.2.1.1.9.1.2.4 1.3.6.1.2.1.1.9.1.2.5 1.3.6.1.2.1.1.9.1.2.6 1.3.6.1.2.1.1.9.1.2.7 1.3.6.1.2.1.1.9.1.2.8 1.3.6.1.2.1.1.9.1.2.9 1.3.6.1.2.1.1.9.1.2.10 1.3.6.1.2.1.1.9.1.3.1 1.3.6.1.2.1.1.9.1.3.2 1.3.6.1.2.1.1.9.1.3.3 1.3.6.1.2.1.1.9.1.3.4 1.3.6.1.2.1.1.9.1.3.5 1.3.6.1.2.1.1.9.1.3.6 1.3.6.1.2.1.1.9.1.3.7 1.3.6.1.2.1.1.9.1.3.8 1.3.6.1.2.1.1.9.1.3.9 1.3.6.1.2.1.1.9.1.3.10 1.3.6.1.2.1.1.9.1.4.1 1.3.6.1.2.1.1.9.1.4.2 1.3.6.1.2.1.1.9.1.4.3 1.3.6.1.2.1.1.9.1.4.4 1.3.6.1.2.1.1.9.1.4.5 1.3.6.1.2.1.1.9.1.4.6 1.3.6.1.2.1.1.9.1.4.7 1.3.6.1.2.1.1.9.1.4.8 1.3.6.1.2.1.1.9.1.4.9 1.3.6.1.2.1.1.9.1.4.10 1.3.6.1.2.1.25.1.1.0 1.3.6.1.2.1.25.1.2.0 1.3.6.1.2.1.25.1.3.0 1.3.6.1.2.1.25.1.4.0 1.3.6.1.2.1.25.1.5.0 1.3.6.1.2.1.25.1.6.0 1.3.6.1.2.1.25.1.7.0 1.3.6.1.2.1.25.1.7.0"    
              

            # For some protocols in Lindenhof the packets become to large for one transmission (like in SNMP)
                # Hence it fragments the bytes and these must be manually put back together into one SNMP packet for analysis
                if any(df['Protocol'] == 'IPv4'):
                    tempIPV4Df = df[df['Protocol'] == 'IPv4']
                    tempIPV4Df = tempIPV4Df.reset_index()
                    for index, row in tempIPV4Df.iterrows():
                        # Find where the IP packet is to be reassembled in original df:
                        ReassemblyNumberIndexStart = row["Info"].find("Reassembled in #")+len("Reassembled in #")
                        ReassemblyNumberIndexEnd = row["Info"].find(']',ReassemblyNumberIndexStart)
                        ReassemblyIndex = int(row["Info"][ReassemblyNumberIndexStart:ReassemblyNumberIndexEnd])
                        # Combine the length of these packets into one packet
                        df.at[df[df["FrameNumber"] == ReassemblyIndex].index.to_list()[0],"Length"] = df.at[df[df["FrameNumber"] == ReassemblyIndex].index.to_list()[0],"Length"]+row["Length"]
                        # remove defragmented IP frame
                        df = df.drop(df[df["FrameNumber"] == row.FrameNumber].index)
                        
                    df.reset_index(inplace=True)
        except Exception:
            print("Error")
                    
        return df