import sys
import time
import random
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt, QObject, pyqtSignal, pyqtSlot, QThread
import pyqtgraph as pg
from pyqtgraph.Qt import QtCore
from datetime import datetime



class Event:
    def __init__(self, ev_type, ip, local_port, transmitted):
        self.ev_type = ev_type
        self.ip = ip
        self.local_port = local_port
        self.transmitted = transmitted


# Custom worker thread
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
                print("line: ", line)
                ev = self.parse_event(line)
                self.update_signal.emit(ev)  # Emit the signal to add the first plot

        except KeyboardInterrupt:
            # Handle the case when the user presses Ctrl+C to interrupt the program
            pass

    def parse_event(self, event: str):
        event_parts = event.split()
        event_type = event_parts[0].strip()
        ip = event_parts[1].strip()
        local_port = event_parts[2]
        transmitted = int(event_parts[3]) if "traffic" in event_type else None
        return Event(event_type, ip, local_port, transmitted)


# Main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(1000)

    def setup_ui(self):
        self.setWindowTitle("Dynamic Plot Example")

        # Create a central widget and a layout
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)

        # Set the central widget
        self.setCentralWidget(central_widget)
        # Initialize the map of plot widgets
        self.plot_widgets = {}

    def add_plot(self, ip, local_port):
        plot_widget = pg.PlotWidget()
        current_time = datetime.now().timestamp()
        self.plot_widgets[ip + local_port] = (plot_widget, [[current_time], [0]])
        self.centralWidget().layout().addWidget(plot_widget)
        plot_widget.setLabel("left", "Received Bytes")
        plot_widget.setLabel("bottom", "Time (s)")
        curve = plot_widget.plot(pen='r')

    def update_plot(self):
        for key in self.plot_widgets:
            plot, data = self.plot_widgets[key]
            plot.plot(data[0], data[1], pen='g')

    def add_datapoint_ingress(self, ip, local_port, received):
        # todo, for now, track only new connections.
        if ip+local_port not in self.plot_widgets:
            return
        (plot, data) = self.plot_widgets[ip + local_port]
        current_time = datetime.now().timestamp()
        data[0].append(current_time)
        data[1].append(received)

    @pyqtSlot(object)
    def store_events(self, event):
        print("Received event", event)
        if event.ev_type == "connect_ingress" or event.ev_type == "connect_egress":
            print("adding new plot")
            self.add_plot(event.ip, event.local_port)
        elif event.ev_type == "traffic_ingress" or "traffic_egress" == event.ev_type:
            print("adding datapoint received")
            self.add_datapoint_ingress(event.ip, event.local_port, event.transmitted)
        else:
            print("not supported yet: ", event)


# Application entry point
if __name__ == '__main__':
    app = QApplication(sys.argv)

    main_window = MainWindow()
    layout = QVBoxLayout(main_window.centralWidget())
    layout.setAlignment(Qt.AlignmentFlag.AlignTop)
    main_window.centralWidget().setLayout(layout)
    main_window.show()

    plot_thread = PlotThread()

    # Connect the update signal to the slot in the main window
    plot_thread.update_signal.connect(main_window.store_events)

    plot_thread.start()

    sys.exit(app.exec())
