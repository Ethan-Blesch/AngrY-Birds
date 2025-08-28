from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

if TYPE_CHECKING:
    from collections.abc import Iterator

    from angr.sim_manager import SimulationManager

    from angrmanagement.ui.widegts.qblock import QBlock
    from angrmanagement.ui.workspace import Workspace

from .popup import ScanDialog

class MenuOptions():
    def newScan(project):
        dialog = ScanDialog(project)
        dialog.setWindowTitle("AngrY Birds - New scan")
        dialog.exec()
