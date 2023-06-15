import io
import sys

import requests
from PyQt6.QtWebEngineCore import QWebEnginePage
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QHBoxLayout, QScrollArea
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, QThread, QSize, QUrl, QObject
import pyqtgraph as pg
import folium
from pyqtgraph.Qt import QtCore
from datetime import datetime
from dataclasses import dataclass


## todo:
# at the beginning of the ebpf, we might have missed some connect call, we can lookup the pids for the local port
# in proc fs.

@dataclass
class SyscallEvent:
    function: str
    ip: str
    pid: int


@dataclass
class TransmissionPacket:
    direction: str
    ip: str
    local_port: str
    transmitted: int


@dataclass
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
    else:
        raise RuntimeError("Could not get my ip address")


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
            print("waiting")
            for line in sys.stdin:
                line = line.strip()  # Remove leading/trailing whitespace
                # print(f"line: '{line}'")
                ev = parse_event(line)
                self.update_signal.emit(ev)  # Emit the signal to add the first plot

        except KeyboardInterrupt:
            # Handle the case when the user presses Ctrl+C to interrupt the program
            pass

class ConsoleLogger(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)

    @pyqtSlot(QWebEnginePage.JavaScriptConsoleMessageLevel, str, int, str)
    def log_message(self, level, message, line_number, source_id):
        print(f"Console [{level}]: {message} (line {line_number} in {source_id})")


class WebPage(QWebEnginePage):
    def __init__(self, parent=None):
        super().__init__(parent)

    def javaScriptConsoleMessage(self, level, message, line_number, source_id):
        self.emit_console_message(level, message, line_number, source_id)

    console_message = pyqtSignal(QWebEnginePage.JavaScriptConsoleMessageLevel, str, int, str)

    def emit_console_message(self, level, message, line_number, source_id):
        self.console_message.emit(level, message, line_number, source_id)

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
        self.my_ip = get_my_ip()
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

        script = f"mapObj.addMarker('{self.my_ip}', {latitude}, {longitude});"
        self.webView.page().loadFinished.connect(lambda: self.webView.page().runJavaScript(script))

    def geolocate_ip(self, ip_address):
        import geocoder
        location = geocoder.ip(ip_address)
        print(ip_address, location)
        latitude, longitude = location.latlng
        return (latitude, longitude)

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
                        maxZoom: 3,
                        attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                    }).addTo(map);

    
                        return {
                            addMarker: addMarker,
                            removeMarker: removeMarker,
                            addLine: addLine
                        };
                    }
    
                    function addMarker(ip, lat, lng) {
                        console.log("addMarker", ip, lat, lng);
                        var marker = L.marker([lat, lng]).addTo(map);
                        marker.bindPopup(ip);
                        markers[ip] = marker;
                    }
    
                    function removeMarker(ip) {
                        console.log("removeMarker", ip);
                        var marker = markers[ip];
                        if (marker) {
                            map.removeLayer(marker);
                            delete markers[ip];
                        }
                    }
    
                    function addLine(startLat, startLng, endLat, endLng) {
                        console.log("addLine", startLat, startLng, endLat, endLng);
                        var start = L.latLng(startLat, startLng);
                        var end = L.latLng(endLat, endLng);
                        var line = L.polyline([start, end], {color: 'red'}).addTo(map);
                        lines[startLat + ',' + startLng + '-' + endLat + ',' + endLng] = line;
                    }
                var mapObj = initMap();</script>
            </body>
            </html>
            """

    def add_ip(self, dest_ip_address):
        if dest_ip_address in self.ip_coordinates:
            print("already have this ip")
            return
        print("dest ip: " + dest_ip_address)
        self.ip_coordinates[dest_ip_address] = self.geolocate_ip(dest_ip_address.split(":")[0])
        dest_latitude, dest_longitude = self.ip_coordinates[dest_ip_address]

        script = f"mapObj.addMarker('{dest_ip_address}', {dest_latitude}, {dest_longitude});"
        self.webView.page().loadFinished.connect(lambda: self.webView.page().runJavaScript(script))

        latitude, longitude = self.ip_coordinates[self.my_ip]

        script = f"mapObj.addLine({latitude}, {longitude}, {dest_latitude}, {dest_longitude});"
        self.webView.page().loadFinished.connect(lambda: self.webView.page().runJavaScript(script))

    def remove_ip(self, ip_address):
        if ip_address in self.ip_coordinates:
            del self.ip_coordinates[ip_address]

            script = f"mapObj.removeMarker('{ip_address}');"
            self.webView.page().runJavaScript(script)

    @pyqtSlot(object)
    def store_events(self, event):
        if type(event) is ControlPacketEvent and event.direction == "ingress":
            print("Received event", event)
            if event.is_fin_packet:
                self.add_ip(event.ip)
            else:
                self.remove_ip(event.ip)


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
