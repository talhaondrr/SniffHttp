import tkinter as tk
from tkinter import filedialog
import threading
from scapy.layers import http
from scapy.all import sniff, IP
import argparse
import time
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.geometry("800x600")
        self.root.title('Network Traffic Analyzer')

        self.label = tk.Label(root, text='Network Traffic Analysis', font=('Arial', 18, 'bold'))
        self.label.pack(pady=10)

        self.text_area = tk.Text(root, width=80, height=20)
        self.text_area.pack()

        self.save_button = tk.Button(root, text='Save', command=self.save_file)
        self.save_button.pack(pady=5)

        self.catch_button = tk.Button(root, text='Catch', command=self.catch_snapshot)
        self.catch_button.pack(pady=5)

        self.exit_button = tk.Button(root, text='Exit', command=self.root.destroy)
        self.exit_button.pack(pady=5)

        self.G = nx.DiGraph()

        self.listen_thread = threading.Thread(target=self.listen_traffic)
        self.listen_thread.daemon = True
        self.listen_thread.start()

    def save_file(self):
        content = self.text_area.get("1.0", tk.END)
        threading.Thread(target=self.save_file_thread, args=(content,)).start()

    def save_file_thread(self, content):
        file = filedialog.asksaveasfile(filetypes=[('text file', '*.txt')], defaultextension='.txt', title='Save captured data')
        if file:
            file.write(content)
            file.close()

    def catch_snapshot(self):
        current_content = self.text_area.get("1.0", tk.END)
        graph_snapshot = self.G.copy()
        
        # Anlık metin dosyası penceresini oluştur
        text_window = TextSnapshotWindow(self.root, current_content)
        
        # Grafik görüntüsü penceresini oluştur
        graph_window = GraphSnapshotWindow(self.root, graph_snapshot)

    def get_interface(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--interface", dest="interface", help="specify the interface")
        arguments = parser.parse_args()
        print(arguments)
        return arguments.interface

    def listen_traffic(self):
        iface = self.get_interface()
        sniff(iface=iface, store=False, prn=self.process_packet)

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host.decode("utf-8")
                path = packet[http.HTTPRequest].Path.decode("utf-8")
                method = packet[http.HTTPRequest].Method.decode("utf-8")
                request_info = f"Method: {method} URL: {url}{path}"
            else:
                request_info = ""

            timestamp = packet.time
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

            output = f"Time: {time_str} Source IP: {src_ip}  Destination IP: {dst_ip}  {request_info}\n"
            self.text_area.insert(tk.END, output)
            self.text_area.see(tk.END)

            self.G.add_edge(src_ip, dst_ip)
            self.plot_graph()

    def plot_graph(self):
        plt.clf()
        pos = nx.spring_layout(self.G)

        node_style = {'node_color': 'blue', 'node_shape': 'o'}
        edge_style = {'edge_color': 'gray', 'arrowsize': 20}

        nx.draw_networkx_nodes(self.G, pos, node_size=500, nodelist=self.G.nodes, **node_style)
        nx.draw_networkx_edges(self.G, pos, **edge_style)
        nx.draw_networkx_labels(self.G, pos)

        plt.title("Network Traffic Visualization")
        plt.pause(0.1)

    def start(self):
        self.root.mainloop()

class TextSnapshotWindow(tk.Toplevel):
    def __init__(self, parent, content):
        super().__init__(parent)
        self.title("Text Snapshot Window")
        
        self.text_area = tk.Text(self, height=20, width=50)
        self.text_area.insert("1.0", content)
        self.text_area.pack(pady=10)
        
        self.save_button = tk.Button(self, text="Save Text", command=self.save_file)
        self.save_button.pack(pady=10)

    def save_file(self):
        content = self.text_area.get("1.0", tk.END)
        file = filedialog.asksaveasfile(filetypes=[('text file', '*.txt')], defaultextension='.txt', title='Save captured data')
        if file:
            file.write(content)
            file.close()

class GraphSnapshotWindow(tk.Toplevel):
    def __init__(self, parent, graph_snapshot):
        super().__init__(parent)
        self.title("Graph Snapshot Window")

        self.graph_snapshot = graph_snapshot
        self.plot_graph()

        self.save_graph_button = tk.Button(self, text="Save Graph", command=self.save_graph)
        self.save_graph_button.pack(pady=10)

    def save_graph(self):
        file = filedialog.asksaveasfile(filetypes=[('PNG file', '*.png')], defaultextension='.png', title='Save graph')
        if file:
            plt.figure(figsize=(8, 6))
            pos = nx.spring_layout(self.graph_snapshot)
            node_style = {'node_color': 'blue', 'node_shape': 'o'}
            edge_style = {'edge_color': 'gray', 'arrowsize': 20}

            nx.draw_networkx_nodes(self.graph_snapshot, pos, node_size=500, nodelist=self.graph_snapshot.nodes, **node_style)
            nx.draw_networkx_edges(self.graph_snapshot, pos, **edge_style)
            nx.draw_networkx_labels(self.graph_snapshot, pos)

            plt.title("Network Traffic Visualization")
            plt.savefig(file.name)
            plt.close()

    def plot_graph(self):
        figure = plt.figure(figsize=(8, 6))
        pos = nx.spring_layout(self.graph_snapshot)
        node_style = {'node_color': 'blue', 'node_shape': 'o'}
        edge_style = {'edge_color': 'gray', 'arrowsize': 20}

        nx.draw_networkx_nodes(self.graph_snapshot, pos, node_size=500, nodelist=self.graph_snapshot.nodes, **node_style)
        nx.draw_networkx_edges(self.graph_snapshot, pos, **edge_style)
        nx.draw_networkx_labels(self.graph_snapshot, pos)

        plt.title("Network Traffic Visualization")
        
        canvas = FigureCanvasTkAgg(figure, self)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    app.start()
