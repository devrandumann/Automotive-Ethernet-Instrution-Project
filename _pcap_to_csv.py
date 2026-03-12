import pandas as pd
from scapy.all import PcapReader, IP
import os

# List of PCAP files to process
pcap_files = [
    "driving_01_injected.pcap",
    "driving_01_original.pcap",
    "driving_02_injected.pcap",
    "driving_02_original.pcap",
    "indoors_01_injected.pcap",
    "indoors_01_original.pcap",
    "indoors_02_injected.pcap",
    "indoors_02_original.pcap",
    "single-MPEG-frame.pcap"
]

def process_pcap_files(file_list):
    dataset_rows = []
    
    # Locate the directory where the script is running
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Working Directory: {base_dir}")

    for filename in file_list:
        full_path = os.path.join(base_dir, filename)

        if not os.path.exists(full_path):
            print(f"WARNING: {filename} not found, skipping.")
            continue
        
        print(f"\n>> Processing: {filename}")
        
        # Labeling Logic: 0 for Normal, 1 for Attack (Injected)
        if "original" in filename:
            label = 0
        elif "injected" in filename:
            label = 1
        else:
            label = 0 

        try:
            # Read PCAP file
            with PcapReader(full_path) as pcap:
                previous_time = 0
                pkt_count = 0
                
                for pkt in pcap:
                    pkt_count += 1
                    
                    # Show progress every 1000 packets
                    if pkt_count % 1000 == 0:
                        print(f"   ... {pkt_count} packets processed", end='\r')

                    try:
                        time_epoch = float(pkt.time)
                        frame_len = len(pkt)
                        
                        # Calculate Delta Time
                        if previous_time == 0:
                            delta_time = 0.0
                        else:
                            delta_time = time_epoch - previous_time
                        previous_time = time_epoch

                        # Extract Protocol
                        protocol = 0
                        if pkt.haslayer(IP):
                            protocol = pkt[IP].proto
                        
                        row = {
                            "FileName": filename,
                            "Time": time_epoch,
                            "DeltaTime": delta_time,
                            "Length": frame_len,
                            "Protocol": protocol,
                            "Label": label
                        }
                        dataset_rows.append(row)
                        
                    except Exception:
                        continue
                
                print(f"\n   Completed! Total {pkt_count} packets extracted.")
                
        except Exception as e:
            print(f"\nFile Error: {e}")

    # Create DataFrame and Save to CSV
    if len(dataset_rows) == 0:
        print("\nERROR: No data extracted!")
        return

    print("\nGenerating CSV file...")
    df = pd.DataFrame(dataset_rows)
    
    output_file = os.path.join(base_dir, "dataset_automotive.csv")
    df.to_csv(output_file, index=False)
    
    print(f"SUCCESS! Data saved to '{output_file}'.")
    print(f"Total Rows: {len(df)}")
    if "Label" in df.columns:
        print("Label Distribution:")
        print(df["Label"].value_counts())

if __name__ == "__main__":
    process_pcap_files(pcap_files)