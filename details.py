from PySide6.QtCore import Qt, QCoreApplication, QMetaObject, QRect, QPoint
from PySide6.QtGui import QIcon, QAction
from PySide6.QtWidgets import *
from .angrybirds import *



class StateInput(QTreeWidgetItem):
    def __init__(self, variable):
        super().__init__(["Placeholder input name"])
        print(type(variable))
        isSymbolic = True

        self.addChild(QTreeWidgetItem(["Symbolic: \t(placeholder)"]))
        self.addChild(QTreeWidgetItem(["Contents: \t(placeholder)"]))
        self.addChild(QTreeWidgetItem(["From: \t(placeholder)"]))

class DetailsPopup(QDialog):
    def __init__(self, write):
        super().__init__()


        self.setWindowTitle("Memory write at rip=" + hex(write.rip))
        self.setMinimumWidth(300)

        layout = QVBoxLayout(self)

        # Create the tree widget
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)  # Hide the header
        layout.addWidget(self.tree)

        # Add top-level items
        parent1 = QTreeWidgetItem(["Control flow"])

        backtrace = QTreeWidgetItem(["Backtrace"])
        parent1.addChild(backtrace)
        backtrace.addChild(QTreeWidgetItem([write.backtrace]))


        parent2 = QTreeWidgetItem(["Program inputs"])
        stdin = QTreeWidgetItem(["stdin"])
        stdin.addChild(QTreeWidgetItem([write.stdin.decode("unicode-escape")]))
        
        # Construct program inputs

        parent2.addChild(stdin)

       

        parent3 = QTreeWidgetItem(["Issues"])

        for issue in write.issues:
            parent3.addChild(QTreeWidgetItem([str(issue)]))
        

        self.tree.addTopLevelItem(parent1)
        self.tree.addTopLevelItem(parent2)
        self.tree.addTopLevelItem(parent3)

        # Optional: Expand all
        self.tree.expandAll()

        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)

