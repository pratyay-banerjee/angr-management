import logging

from PySide2.QtWidgets import QLabel, QHBoxLayout, QSizePolicy, QGraphicsItem, QGraphicsSimpleTextItem
from PySide2.QtGui import QCursor, QPainter, QColor
from PySide2.QtCore import Qt, SIGNAL, QRectF

from angr.analyses.disassembly import Value

from .qgraph_object import QCachedGraphicsItem
from .qoperand import QOperand
from ...utils import should_display_string_label, get_string_for_display, get_comment_for_display

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class QInstruction(QCachedGraphicsItem):

    GRAPH_ADDR_SPACING = 20
    GRAPH_MNEMONIC_SPACING = 10
    GRAPH_OPERAND_SPACING = 2
    GRAPH_COMMENT_STRING_SPACING = 5

    INTERSPERSE_ARGS = ', '

    LINEAR_INSTRUCTION_OFFSET = 120

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, insn, out_branch, config, mode='graph', parent=None):
        super().__init__(parent=parent)

        # initialization
        self.workspace = workspace
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.insn = insn
        self.out_branch = out_branch
        self._config = config
        self.mode = mode

        self.selected = False

        # all "widgets"
        self._addr = None
        self._addr_width = None
        self._mnemonic = None
        self._mnemonic_width = None
        self._operands = [ ]
        self._string = None
        self._string_width = None
        self._comment = None
        self._comment_width = None

        self._init_widgets()

        #self.setContextMenuPolicy(Qt.CustomContextMenu)
        #self.connect(self, SIGNAL('customContextMenuRequested(QPoint)'), self._on_context_menu)

    def refresh(self):
        super(QInstruction, self).refresh()

        for operand in self._operands:
            operand.refresh()

        #self._update_size()
        self._init_widgets()
        self._layout_operands()

    def set_comment(self, new_text):
        self._comment = new_text
        self._comment_width = self._config.disasm_font_width * len(self._comment)
        self._update_size()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            _l.debug('Received click of instruction at address 0x%x', self.addr)
            if self.workspace.instance.selected_addr != self.addr:
                self.workspace.instance.selected_addr = self.addr
            else:
                self.workspace.instance.selected_addr = None
        else:
            super().mousePressEvent(event)


    # def on_mouse_pressed(self, button, pos):
    #     if button == Qt.LeftButton:
    #         # left click

    #         # is it on one of the operands?
    #         for op in self._operands:
    #             if op.x <= pos.x() < op.x + op.width:
    #                 op.on_mouse_pressed(button, pos)
    #                 return

    #         _l.debug('detected mouse press')
    #         if self.workspace.instance.selected_addr != self.insn.addr:
    #             _l.debug('Click detected! Setting...')
    #             self.workspace.instance.selected_addr = self.insn.addr
    #         else:
    #             _l.debug('Click detected! Unsetting...')
    #             self.workspace.instance.selected_addr = None
    #     elif button == Qt.RightButton:
    #         # right click
    #         # display the context menu
    #         self.disasm_view.instruction_context_menu(self.insn, QCursor.pos())

    # def on_mouse_released(self, button, pos):
    #     pass

    # def on_mouse_doubleclicked(self, button, pos):

    #     if button == Qt.LeftButton:
    #         # left double click

    #         # is it on one of the operands?
    #         for op in self._operands:
    #             if op.x <= pos.x() < op.x + op.width:
    #                 op.on_mouse_doubleclicked(button, pos)
    #                 return

    #
    # Private methods
    #

    @property
    def addr(self):
        return self.insn.addr


    @property
    def insn_backcolor(self):
        r, g, b = None, None, None

        # First we'll check for customizations
        if self.disasm_view.insn_backcolor_callback:
            is_selected = int(self._addr, 16) == self.workspace.instance.selected_addr
            r, g, b = self.disasm_view.insn_backcolor_callback(self.insn.addr, is_selected)

        # Fallback to defaults if we get Nones from the callback
        if r is None or g is None or b is None:
            if int(self._addr, 16) == self.workspace.instance.selected_addr:
                r, g, b = 0xef, 0xbf, 0xba

        return r, g, b

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        if self.addr == self.workspace.instance.selected_addr:
            painter.setBrush(Qt.red)
            painter.setPen(Qt.red)
            painter.drawRect(0, 0, self.width, self.height)
        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.disasm_font)
        painter.setBrush(Qt.black)
        painter.setPen(Qt.black)
        y = self._config.disasm_font_ascent
        painter.drawText(0, y, self._mnemonic)
        for operand in self._operands[:-1]:
            endpos = operand.pos().x() + operand.width
            painter.drawText(endpos, y, self.INTERSPERSE_ARGS)


    def _init_widgets(self):
        self._operands.clear()

        self._addr = "%08x" % self.insn.addr
        self._addr_width = self._config.disasm_font_width * len(self._addr)
        self._mnemonic = self.insn.mnemonic.render()[0]
        self._mnemonic_width = self._config.disasm_font_width * len(self._mnemonic)

        for i, operand in enumerate(self.insn.operands):
            is_branch_target = self.insn.type in ('branch', 'call') and i == self.insn.branch_target_operand
            is_indirect_branch = self.insn.branch_type == 'indirect'
            branch_targets = None
            if is_branch_target:
                if self.out_branch is not None:
                    branch_targets = self.out_branch.targets
                else:
                    # it does not create multiple branches. e.g., a call instruction
                    if len(operand.children) == 1 and type(operand.children[0]) is Value:
                        branch_targets = (operand.children[0].val,)
            qoperand = QOperand(self.workspace, self.func_addr, self.disasm_view, self.disasm, self.infodock,
                               self.insn, operand, i, is_branch_target, is_indirect_branch, branch_targets, self._config,
                               parent=self)
            self._operands.append(qoperand)

        if should_display_string_label(self.workspace.instance.cfg, self.insn.addr):
            # yes we should display a string label
            self._string = get_string_for_display(self.workspace.instance.cfg, self.insn.addr)
            self._string_width = self._config.disasm_font_width * len(self._string)

        self._comment = get_comment_for_display(self.workspace.instance.cfg.kb, self.insn.addr)
        if self._comment is not None:
            self._comment_width = self._config.disasm_font_width * len(self._comment)

        #self._mnemonic_item = QGraphicsSimpleTextItem(self._mnemonic, parent=self)
        #self._mnemonic_item.setFont(self._config.code_font)

        x = 0
        #self._mnemonic_item.setPos(0, 0)
        x = self._config.disasm_font_width * 10
        intersperse_width = self._config.disasm_font_metrics.width(self.INTERSPERSE_ARGS)
        if len(self._operands) > 0:
            for operand in self._operands[:-1]:
                operand.setPos(x, 0)
                x += operand.boundingRect().width() + intersperse_width
            last_operand = self._operands[-1]
            last_operand.setPos(x, 0)
            x += last_operand.boundingRect().width()
        self._width = x
        self._height = self._config.disasm_font_height

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
