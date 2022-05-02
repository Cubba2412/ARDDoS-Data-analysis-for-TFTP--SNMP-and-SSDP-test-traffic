from scapy.all import *
import pandas as pd
from datetime import datetime

packetTypes = list(scapy.layers.l2.ETHER_TYPES.values())
packetTypes.extend(["TFTP","DNS","TFTP opcode","TFTP Read Request"])

def readPcapWithoutTshark(filename,Protocols=None,sport=None,dport=None):
    """ Protocol: Str
         Filter for specific protocols
        
        sport: Integer
         Filter for specific source port
        
        dport: Integer
         Filter for specific destination port
         """
    # rdpcap comes from scapy and loads in our pcap file
    packets = rdpcap(filename)

    # Let's iterate through every packet
    dsts = [] # Destination IPs
    srcs = [] # Source IPs
    packetlen = [] # packet lengths
    times = [] # Time of occurence since start of capture
    protos = [] # Protocol type of the packet

    for packet in packets:
        layernames = [pack._name for pack in packet.layers()]
        # Scapy sometimes wants to place the protocol names in different places, so we have to search for them....
        if None in layernames:
            NoneIndex = layernames.index(None)
            layernames[NoneIndex] = packet.getlayer(NoneIndex).name
        # If not in application layer it will be in the network layer
        proto = set(layernames) & set(packetTypes)
        if len(proto) < 1:
            protocol = 'Unknown'
        else:
            protocol = next(iter(proto))
        if packet.getlayer(IP) != None:
            packsrc = packet.payload.src
            packdst = packet.payload.dst
        else:
            packsrc = packet.src
            packdst = packet.dst
        packlen = len(packet)
        ## Since datetime is limited to microseconds and not nanoseconds we have to perform some magic
        # First we extract the numbers after the decimal point in the "decimal" python type value that represents the time accurately
        preciseDelta = pd.Timedelta(packet.time.to_eng_string().split('.')[1])
        # We then extract the nanoseconds and milliseconds from this
        nano = pd.to_timedelta(preciseDelta.nanoseconds*1e3)
        milli = pd.to_timedelta(preciseDelta.total_seconds() * 1e4,unit='s')
        # Finally we convert the python decimal into a timestamp with precision only down to seconds, and then add in the milli- and nanoseconds to that timestamp
        time_dt = pd.to_datetime(pd.to_datetime(datetime.fromtimestamp(packet.time).replace(microsecond=0)) + milli + nano,unit='ns')
        # And magically timestamp suddenly contains accurate nanoseconds (No idea why it othwerwise rounds off the precision in a wrong way)
        if Protocols != None:
            if isinstance(Protocols,list):
                protoPresent = any(prot in packet for prot in Protocols)
            else:
                protoPresent = Protocols in packet
            if protoPresent:
                srcs.append(packsrc)
                dsts.append(packdst)
                protos.append(protocol)
                packetlen.append(packlen)
                times.append(time_dt)
        else:
            srcs.append(packsrc)
            dsts.append(packdst)
            protos.append(protocol)
            packetlen.append(packlen)
            times.append(time_dt)


    df = pd.DataFrame(
        {'time':times,
        'src': srcs,
        'dst': dsts,
        'protocol':protos,
        'length': packetlen
        })
    return df

attackFilename = './pcap_tftp_own_tool/level0/tftp_level0_13_seconds_attacker.pcapng'
attackerDf = readPcap(attackFilename,["TFTP opcode","TFTP Read Request"])
attackerDf = attackerDf.loc[attackerDf['protocol'].isin(["TFTP Read Request","TFTP opcode"])]
attackerBytesSent = attackerDf["length"].sum()