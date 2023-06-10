import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, QThread
import pyqtgraph as pg
from pyqtgraph.Qt import QtCore
from datetime import datetime
from dataclasses import dataclass, field


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
                print(f"line: '{line}'")
                ev = parse_event(line)
                self.update_signal.emit(ev)  # Emit the signal to add the first plot

        except KeyboardInterrupt:
            # Handle the case when the user presses Ctrl+C to interrupt the program
            pass


# Main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dynamic Plot Example")

        # Create a central widget and a layout
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)

        # Set the central widget
        self.setCentralWidget(central_widget)
        # Initialize the map of plot widgets
        self.plot_widgets = {}
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(1000)

    def add_plot(self, ip, local_port):
        plot_widget = pg.PlotWidget()
        current_time = datetime.now().timestamp()
        self.plot_widgets[ip + local_port] = (plot_widget, [[current_time], [0]])
        self.centralWidget().layout().addWidget(plot_widget)
        plot_widget.setLabel("left", "Received Bytes")
        plot_widget.setLabel("bottom", "Time (s)")
        _curve = plot_widget.plot(pen='r')

    def update_plot(self):
        for key in self.plot_widgets:
            plot, data = self.plot_widgets[key]
            plot.plot(data[0], data[1], pen='g')

    def add_datapoint_ingress(self, ip, local_port, received):
        # todo, for now, track only new connections.
        if ip + local_port not in self.plot_widgets:
            return
        (plot, data) = self.plot_widgets[ip + local_port]
        current_time = datetime.now().timestamp()
        data[0].append(current_time)
        data[1].append(received)

    @pyqtSlot(object)
    def store_events(self, event):
        print("Received event", event)
        if type(event) is SyscallEvent:
            print("adding syscall event")
            if event.function == "connect":
                self.add_plot(event.ip, event.pid)
        elif type(event) is ControlPacketEvent:
            print("adding control event")
            if not event.is_fin_packet:
                self.add_plot(event.ip, event.local_port)
        elif type(event) is TransmissionPacket:
            print("adding transmission event")
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
