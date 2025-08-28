from PySide6.QtCore import Qt, QCoreApplication, QMetaObject, QRect, QPoint, QThread, Signal
from PySide6.QtGui import QIcon, QAction, QColor
from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QTableWidget, QTableWidgetItem, QMenu, QLineEdit, QFormLayout
from .angrybirds import *
from .details import DetailsPopup



class Scan(QThread):
    finished = Signal()

    def loadData(self, project, tableCallback):
        self.project = project
        self.tableCallback = tableCallback

    def run(self):
        print("Hello, World!")
        writes = find_writes(self.project, self.tableCallback)
        self.tableCallback(writes)

class ScanDialog(QDialog):


    
    def __init__(self, project):
        super().__init__()
        self.scanner = Scan()
        #Instance data and widgets
        self.project = project
        self.button = QPushButton("Scan")
        self.table = QTableWidget()
        #Window setup
        self.setWindowTitle("Basic QDialog")
        self.setGeometry(100, 100, 900, 500)
        
        #Connect button
        self.button.clicked.connect(self.load_data)

        #Initialize table
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["RIP", "Function", "Possible range", "Symbolic data?", "Symbolic addr?", "Symbolic size?", "Score"])
        self.table.setRowCount(0)
        self.table.resizeColumnsToContents()


        # Initialize left side of window 
        left_layout = QVBoxLayout()
        
        left_layout.addWidget(self.button)
        
        left_layout.addStretch()

        #Initialize main layout
        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout)
        main_layout.addWidget(self.table)

        self.setLayout(main_layout)

    def populateRow(self, write, rowNum):

        self.table.setItem(rowNum, 0, QTableWidgetItem(hex(write.rip)))
        self.table.setItem(rowNum, 1, QTableWidgetItem(write.function.name))
        self.table.setItem(rowNum, 2, QTableWidgetItem(hex(write.rangeStart) + " to " + hex(write.rangeEnd)))

        def boolToYesNo(x):
            return "yes" if x else "no"

        self.table.setItem(rowNum, 3, QTableWidgetItem(boolToYesNo(write.symData)))
        self.table.setItem(rowNum, 4, QTableWidgetItem(boolToYesNo(write.symAddr)))
        self.table.setItem(rowNum, 5, QTableWidgetItem(boolToYesNo(write.symLen)))
        self.table.setItem(rowNum, 6, QTableWidgetItem(str(write.score())))
        if write.score() > 0:
            for col in range(self.table.columnCount()):
                self.table.item(rowNum, col).setBackground(QColor("red"))

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.customTableContext)
        self.table.resizeColumnsToContents()

    def load_data(self):
        #TODO: Add proper error handling for self.project == null
        #self.writes = find_writes(self.project, targetFunction)


        self.scanner.loadData(self.project, self.updateTable)
        self.scanner.start()

    def updateTable(self, writes):
        self.writes = writes;
        self.table.setRowCount(len(writes))

        for rowNum, write in enumerate(writes):
            self.populateRow(write, rowNum);

        self.makeTableReadOnly(self.table)
        self.table.resizeColumnsToContents()

    def makeTableReadOnly(self, table: QTableWidget):
        #There's probably a better way to make a table read-only, but chatgpt wrote this and it works ¯\_(ツ)_/¯
        rows = table.rowCount()
        columns = table.columnCount()

        for row in range(rows):
            for col in range(columns):
                item = table.item(row, col)
                if item is None:
                    # If no item exists yet, create one
                    item = QTableWidgetItem()
                    table.setItem(row, col, item)
                # Remove the ItemIsEditable flag
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)


    def customTableContext(self, pos: QPoint):
        item = self.table.itemAt(pos)

        if item:
            global_pos = self.table.viewport().mapToGlobal(pos)

            # Create the menu
            menu = QMenu()
            action1 = QAction("More details", self)
            write = self.writes[item.row()]
            # Optional: connect actions
            action1.triggered.connect(lambda: self.moreDetails(write))
            #action2.triggered.connect(lambda: self.custom_action(item, 2))
            
            menu.addAction(action1)
            #menu.addAction(action2)

            # Show the menu
            menu.exec(global_pos)

    def moreDetails(self, write):
        dialog = DetailsPopup(write)
        dialog.exec()
