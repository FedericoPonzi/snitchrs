import sys

import requests
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QScrollArea
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, QThread, QSize, QUrl

from dataclasses import dataclass


## todo:
# at the beginning of the ebpf, we might have missed some connect call, we can lookup the pids for the local port
# in proc fs.

@dataclass(eq=True)
class SyscallEvent:
    function: str
    ip: str
    pid: int


@dataclass(eq=True)
class TransmissionPacket:
    direction: str
    ip: str
    local_port: str
    transmitted: int


@dataclass(eq=True)
class ControlPacketEvent:
    is_fin_packet: str
    direction: str
    ip: str
    local_port: str


def get_my_ip():
    response = requests.get('http://ipinfo.io/json')
    if response.status_code == 200:
        ip_address = response.json()['ip']
        return ip_address
    # it looks like https is showing ipv6, so to get ipv4 we need http
    response = requests.get('http://ipv4.icanhazip.com/')
    if response.status_code == 200:
        return response.text.strip()
    raise RuntimeError("Could not get my ip address: "+ str(response))



# Custom worker thread
def parse_event(event: str):
    event_parts = event.split()
    event_type = event_parts[0].strip()
    if event_type in ["egress_connect", "ingress_connect", "egress_disconnect", "ingress_disconnect"]:
        [direction, func] = event_type.split("_")
        ip = event_parts[1].strip()
        local_port = event_parts[2]
        return ControlPacketEvent(func == "disconnect", direction, ip, local_port)
    elif event_type in ["ingress_traffic", "egress_traffic"]:
        # ingress_traffic 162.159.135.234:443 :32998 31745
        direction = event_type.split("_")[0]
        ip = event_parts[1].strip()
        local_port = event_parts[2]
        transmitted = int(event_parts[3])
        return TransmissionPacket(direction, ip, local_port, transmitted)
    elif event_type in ["syscall_connect", "syscall_accept"]:
        # syscall_connect 172.104.141.216:80 364801
        syscall = event_type.split("_")[1]
        ip = event_parts[1].strip()
        pid = event_parts[2]
        return SyscallEvent(syscall, ip, int(pid))
    else:
        print(f"Unknown event type: '{event_type}'")
        return None


class PlotThread(QThread):
    update_signal = pyqtSignal(object)  # Signal to send data to the main thread

    def __init__(self):
        super().__init__()
        self.ip_plots = []

    def run(self):
        try:
            for line in sys.stdin:
                line = line.strip()
                ev = parse_event(line)
                self.update_signal.emit(ev)

        except KeyboardInterrupt:
            # Handle the case when the user presses Ctrl+C to interrupt the program
            pass


@dataclass
class PlotWidgetEntity:
    curve_received: any
    curve_transmitted: any
    received: list
    transmitted: list
    connections: int


# Main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Little Snitchrs")

        self.ip_coordinates = {}
        try:
            self.my_ip = get_my_ip()
        except RuntimeError as e:
            print(e)
            sys.exit(1)
        latitude, longitude = self.geolocate_ip(self.my_ip)
        self.ip_coordinates[self.my_ip] = (latitude, longitude)

        # Create a central widget and a layout
        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll = QScrollArea()
        self.main_widget = QWidget()
        self.scroll.setWidgetResizable(True)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.main_widget.setLayout(self.main_layout)
        self.scroll.setWidget(self.main_widget)

        self.setMinimumSize(QSize(900, 600))

        self.webView = QWebEngineView()
        self.webView.setHtml(self.load_map(latitude, longitude), QUrl("about:blank"))
        self.main_layout.addWidget(self.webView)
        self.webView.setMinimumSize(QSize(900, 600))
        # Set the central widget
        self.setCentralWidget(self.scroll)
        # Initialize the map of plot widgets

        script = f"mapObj.addMarker('HomeSweetHome: {self.my_ip}', {latitude}, {longitude});"
        self.webView.page().loadFinished.connect(lambda: self.webView.page().runJavaScript(script))

    def geolocate_ip(self, ip_address):
        """
        :param ip_address: ipv4 address
        :return: latitude, longitude
        """
        response = requests.get("http://ip-api.com/json/" + ip_address)
        if response.status_code == 200:
            response = response.json()
        return response['lat'], response['lon']

    def load_map(self, latitude, longitude):
        return """
            <!DOCTYPE html>
<html lang="en">
<head>
    <base target="_top">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <title>Quick Start - Leaflet</title>
    
    <link rel="shortcut icon" type="image/x-icon" href="docs/images/favicon.ico" />

    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<style>
        html, body {
            height: 100%;
            margin: 0;
        }
        .leaflet-container {
            height: 400px;
            width: 600px;
            max-width: 100%;
            max-height: 100%;
        }
    </style>
</head>
<body>
    <div id="map" style="width: 100%; height: 100%;"></div>                

    <script>
            
                    var map;
                    var markers = {};
                    var lines = {};
    
                    function initMap() {
                        map = L.map('map').setView([""" + str(latitude) + """, """ + str(longitude) + """], 13);
    
                    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
                        maxZoom: 5,
                        attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                    }).addTo(map);

    
                        return {
                            addMarker: addMarker,
                            removeMarker: removeMarker,
                            addLine: addLine
                        };
                    }
    
                    function addMarker(ip, lat, lng, icon) {
                        var marker = L.marker([lat, lng], icon).addTo(map);
                        marker.bindPopup(ip);
                        markers[ip] = marker;
                    }
    
                    function removeMarker(ip) {
                        var marker = markers[ip];
                        if (marker) {
                            map.removeLayer(marker);
                            delete markers[ip];
                        }
                    }
    
                    function addLine(startLat, startLng, endLat, endLng) {
                        var start = L.latLng(startLat, startLng);
                        var end = L.latLng(endLat, endLng);
                        var line = L.polyline([start, end], {color: 'red'}).addTo(map);
                        lines[startLat + ',' + startLng + '-' + endLat + ',' + endLng] = line;
                    }
                var greenIcon = new L.Icon({
                  iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png',
                  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/images/marker-shadow.png',
                  iconSize: [25, 41],
                  iconAnchor: [12, 41],
                  popupAnchor: [1, -34],
                  shadowSize: [41, 41]
                });
                var mapObj = initMap();</script>
            </body>
            </html>
            """

    def add_ip(self, dest_ip_address):
        if dest_ip_address in self.ip_coordinates:
            print("already have this ip")
            return
        print("dest ip: " + dest_ip_address)
        self.ip_coordinates[dest_ip_address] = self.geolocate_ip(dest_ip_address)
        dest_latitude, dest_longitude = self.ip_coordinates[dest_ip_address]

        script = f"mapObj.addMarker('{dest_ip_address}', {dest_latitude}, {dest_longitude}, {{ icon: greenIcon }});"
        self.webView.page().runJavaScript(script)

        latitude, longitude = self.ip_coordinates[self.my_ip]

        script = f"mapObj.addLine({latitude}, {longitude}, {dest_latitude}, {dest_longitude});"
        self.webView.page().runJavaScript(script)

    def remove_ip(self, ip_address):
        if ip_address not in self.ip_coordinates:
            print("ip not present.")
            return
        del self.ip_coordinates[ip_address]

        script = f"mapObj.removeMarker('{ip_address}');"
        self.webView.page().runJavaScript(script)

    @pyqtSlot(object)
    def store_events(self, event):
        if type(event) is ControlPacketEvent and event.direction == "ingress":
            print("Received event", event)
            event.ip = event.ip.split(":")[0]
            if not event.is_fin_packet:
                self.add_ip(event.ip)


# Application entry point
if __name__ == '__main__':
    app = QApplication(sys.argv)

    main_window = MainWindow()
    main_window.show()

    plot_thread = PlotThread()

    # Connect the update signal to the slot in the main window
    plot_thread.update_signal.connect(main_window.store_events)

    plot_thread.start()

    sys.exit(app.exec())
