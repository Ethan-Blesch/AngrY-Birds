from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount

if TYPE_CHECKING:
    from collections.abc import Iterator

    from angr.sim_manager import SimulationManager

    from angrmanagement.ui.widgets.qblock import QBlock
    from angrmanagement.ui.workspace import Workspace


class AngryBirds(BasePlugin):
    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)

    MENU_BUTTONS = ["Scan memory writes"]

    def handle_clicK_menu(self, idx: int):
        if idx == 0:
            pass

    

        

