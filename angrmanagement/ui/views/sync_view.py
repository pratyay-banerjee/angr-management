
from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QPushButton, QMessageBox

from .view import BaseView
from ..widgets.qteam_table import QTeamTable


class SyncView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('sync', workspace, default_docking_position, *args, **kwargs)

        self.caption = "Sync"

        self._status_label = None  # type: QLabel
        self._team_table = None  # type: QTeamTable

        self._init_widgets()

        self.width_hint = 250

        # subscribe
        self.workspace.instance.sync.users_container.am_subscribe(self._update_users)

    def reload(self):
        self._status_label.setText(self.workspace.instance.sync.status_string)

    #
    # Private methods
    #

    def _init_widgets(self):

        # status
        status_box = QGroupBox(self)
        status_box.setTitle("Status")

        self._status_label = QLabel(self)
        self._status_label.setText(self.workspace.instance.sync.status_string)

        status_layout = QVBoxLayout()
        status_layout.addWidget(self._status_label)

        status_box.setLayout(status_layout)

        # table

        self._team_table = QTeamTable(self.workspace.instance)
        team_box = QGroupBox(self)
        team_box.setTitle("Team")

        # operations

        # pull function button
        pullfunc_btn = QPushButton(self)
        pullfunc_btn.setText("Pull function")
        pullfunc_btn.setToolTip("Pull current function from the selected user")
        pullfunc_btn.clicked.connect(self._on_pullfunc_clicked)

        # push function button
        pushfunc_btn = QPushButton()
        pushfunc_btn.setText('Push function')
        pushfunc_btn.setToolTip("Push current function to the repo")
        pushfunc_btn.clicked.connect(self._on_pushfunc_clicked)

        actions_box = QGroupBox(self)
        actions_box.setTitle("Actions")
        actions_layout = QHBoxLayout()
        actions_layout.addWidget(pullfunc_btn)
        actions_layout.addWidget(pushfunc_btn)
        actions_box.setLayout(actions_layout)

        team_layout = QVBoxLayout()
        team_layout.addWidget(self._team_table)
        team_layout.addWidget(actions_box)
        team_box.setLayout(team_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(team_box)

        self.setLayout(main_layout)

    #
    # Event callbacks
    #

    def _on_pullfunc_clicked(self):
        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        if disasm_view is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine the current function. No disassembly view is open.")
            return

        current_function = disasm_view._current_function
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "No function is current in the disassembly view.")
            return

        # which user?
        u = self._team_table.selected_user()
        if u is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine which user to pull from. "
                                 "Please select a user in the team table first.")
            return

        self.workspace.instance.project.kb.sync.fill_function(current_function, user=u)

        # trigger a refresh
        disasm_view.refresh()

    def _on_pushfunc_clicked(self):

        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        if disasm_view is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine the current function. No disassembly view is open.")
            return

        current_function = disasm_view._current_function
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "No function is current in the disassembly view.")
            return

        func = current_function
        kb = self.workspace.instance.project.kb
        kb.sync.push_function(func)

        # comments
        comments = { }
        for block in func.blocks:
            for ins_addr in block.instruction_addrs:
                if ins_addr in kb.comments:
                    comments[ins_addr] = kb.comments[ins_addr]
        kb.sync.push_comments(comments)
        print(comments)

        # TODO: Fix this
        kb.sync.commit()

    def _update_users(self):
        self._team_table.update_users(self.workspace.instance.sync.users)