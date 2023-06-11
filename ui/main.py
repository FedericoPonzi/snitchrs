import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QHBoxLayout, QScrollArea
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, QThread, QSize
import pyqtgraph as pg
from pyqtgraph.Qt import QtCore
from datetime import datetime
from dataclasses import dataclass, field


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


@dataclass
class PlotWidgetEntity:
    curve_received: any
    curve_transmitted: any
    time_dps: list
    received: list
    transmitted: list


# Main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Little Snitchrs")

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

        # Set the central widget
        self.setCentralWidget(self.scroll)
        # Initialize the map of plot widgets
        self.plot_widgets = {}
        self.pids = []

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(1000)

    def add_row(self, pid):
        widget = QLabel("PID: " + str(pid))
        font = widget.font()
        font.setPointSize(30)
        row = QHBoxLayout()
        row.addWidget(widget)
        row.setAlignment(Qt.AlignmentFlag.AlignTop)
        row.setAlignment(Qt.AlignmentFlag.AlignLeft)


    def remove_row(self, pid):
        del self.plot_widgets[pid]

    def add_plot(self, ip, local_port):
        date_axis = pg.graphicsItems.DateAxisItem.DateAxisItem(orientation='bottom')
        plot_widget = pg.PlotWidget(axisItems={'bottom': date_axis}, )

        current_time = datetime.now().timestamp()

        label = QLabel("PID: " + str(local_port))
        font = label.font()
        font.setPointSize(30)
        row = QHBoxLayout()
        row.addWidget(label)
        row.addWidget(plot_widget)
        row.setAlignment(Qt.AlignmentFlag.AlignTop)
        row.setAlignment(Qt.AlignmentFlag.AlignLeft)

        widget = QWidget()
        widget.setLayout(row)
        widget.setMinimumSize(QSize(500, 150))

        self.main_layout.addWidget(widget)
        plot_widget.setLabel("left", "Received Bytes")
        plot_widget.setLabel("bottom", "Time (s)")

        plot_widget.setLabel("right", "Transmitted Bytes")
        curve_received = plot_widget.plot(pen='r')
        curve_transmitted = plot_widget.plot(pen='r')
        self.plot_widgets[ip + str(local_port)] = PlotWidgetEntity(curve_received, curve_transmitted, [current_time],
                                                                   [0], [0])

    def update_plot(self):
        for key in self.plot_widgets:
            plot_widget_entity = self.plot_widgets[key]
            plot_widget_entity.curve_received.setData(plot_widget_entity.time_dps, plot_widget_entity.received, pen='r',
                                                      symbol='o', symbolPen=None, symbolSize=4, symbolBrush=('r'))
            plot_widget_entity.curve_transmitted.setData(plot_widget_entity.time_dps, plot_widget_entity.transmitted,
                                                         pen='b', symbol='o', symbolPen=None, symbolSize=4,
                                                         symbolBrush=('b'))

    def add_datapoint_ingress(self, ip, local_port, received):
        # todo, for now, track only new connections.
        if ip + local_port not in self.plot_widgets:
            return
        plot_widget_entity = self.plot_widgets[ip + local_port]
        current_time = datetime.now().timestamp()
        plot_widget_entity.time_dps.append(current_time)
        plot_widget_entity.received.append(received)

    def add_datapoint_egress(self, ip, local_port, transmitted):
        if ip + local_port not in self.plot_widgets:
            return
        plot_widget_entity = self.plot_widgets[ip + local_port]
        current_time = datetime.now().timestamp()
        plot_widget_entity.time_dps.append(current_time)
        plot_widget_entity.transmitted.append(transmitted)

    def remove_connection(self, ip, local_port):
        if ip + local_port not in self.plot_widgets:
            return
        del self.plot_widgets[ip + local_port]

    @pyqtSlot(object)
    def store_events(self, event):
        print("Received event", event)
        if type(event) is SyscallEvent:
            if event.function == "connect":
                self.add_plot(event.ip+"1", event.pid)
                self.add_plot(event.ip+"2", event.pid)
                self.add_plot(event.ip, event.pid)
            elif event.function == "accept":
                self.add_plot(event.ip, event.pid)
        elif type(event) is ControlPacketEvent:
            if event.is_fin_packet:
                self.remove_connection(event.ip, event.local_port)
            else:
                # todo: remove
                self.add_plot(event.ip, event.local_port)
        elif type(event) is TransmissionPacket:
            self.add_datapoint_ingress(event.ip, event.local_port, event.transmitted)
        else:
            print("not supported yet: ", event)


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
