# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'test.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

from PySide6.QtCore import Qt, QCoreApplication, QMetaObject, QRect
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QTableWidget, QTableWidgetItem

from .angrybirds import *



class ScanDialog(QDialog):



    def __init__(self, project):
        super().__init__()

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
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["RIP", "Min size", "Max size", "Min addr", "Max addr", "Possible range", "Symbolic data?", "Symbolic addr?", "Symbolic size?"])
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
        self.table.setItem(rowNum, 1, QTableWidgetItem(hex(write.minLen)))
        self.table.setItem(rowNum, 2, QTableWidgetItem(hex(write.maxLen)))
        self.table.setItem(rowNum, 3, QTableWidgetItem(hex(write.minAddr)))
        self.table.setItem(rowNum, 4, QTableWidgetItem(hex(write.maxAddr)))
        self.table.setItem(rowNum, 5, QTableWidgetItem(hex(write.rangeStart) + " to " + hex(write.rangeEnd)))

        def boolToYesNo(x):
            return "yes" if x else "no"

        self.table.setItem(rowNum, 6, QTableWidgetItem(boolToYesNo(write.symData)))
        self.table.setItem(rowNum, 7, QTableWidgetItem(boolToYesNo(write.symAddr)))
        self.table.setItem(rowNum, 8, QTableWidgetItem(boolToYesNo(write.symLen)))
        self.table.resizeColumnsToContents()

    def load_data(self):
        #TODO: Add proper error handling for self.project == null
        writes = find_writes(self.project)

        self.table.setRowCount(len(writes))

        for rowNum, write in enumerate(writes):
            self.populateRow(write, rowNum);
