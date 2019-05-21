import logging

from PySide2.QtGui import QPainter, QLinearGradient, QColor, QBrush, QPen
from PySide2.QtCore import QPointF, Qt, QRectF, Slot
from PySide2.QtWidgets import QGraphicsItem

from angr.analyses.disassembly import Instruction
from angr.sim_variable import SimRegisterVariable

from ...utils import (
    get_label_text, get_block_objects, address_to_text, get_out_branches_for_insn,
    get_string_for_display, should_display_string_label,
)
from ...utils.block_objects import Variables, PhiVariable, Label
from ...config import Conf
from .qinstruction import QInstruction
from .qblock_label import QBlockLabel
from .qphivariable import QPhiVariable
from .qvariable import QVariable


_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

class QBlock(QGraphicsItem):
    TOP_PADDING = 0
    BOTTOM_PADDING = 0
    GRAPH_LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, addr, cfg_nodes, out_branches, parent=None):
        super().__init__(parent=parent)

        # initialization
        self.workspace = workspace
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.addr = addr
        self.cfg_nodes = cfg_nodes
        self.out_branches = out_branches

        self.workspace.instance.selected_addr_updated.connect(self.refresh_if_contains_addr)
        self.workspace.instance.selected_operand_updated.connect(self.refresh)

        self._config = Conf

        self.objects = [ ]  # instructions and labels
        self.addr_to_insns = { }
        self.addr_to_labels = { }

        self._init_widgets()

        self._rect = None

    #
    # Properties
    #

    @property
    def mode(self):
        raise NotImplementedError

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    #
    # Public methods
    #

    @Slot(int)
    def refresh_if_contains_addr(self, addr1, addr2):
        if addr1 in self.addr_to_insns or addr2 in self.addr_to_insns:
            self.refresh()

    def refresh(self):
        self._init_widgets()
        self.update()

    def update_label(self, label_addr):
        label = self.addr_to_labels.get(label_addr, None)
        if label is not None:
            label.label = self.disasm.kb.labels[label_addr]
        else:
            raise Exception('Label at address %#x is not found.' % label_addr)

    def instruction_position(self, insn_addr):
        if insn_addr in self.addr_to_insns:
            insn = self.addr_to_insns[insn_addr]
            x = self.x + self.GRAPH_LEFT_PADDING
            y = self.y + self.TOP_PADDING + self.objects.index(insn) * (self._config.disasm_font_height + self.SPACING)
            return x, y

        return None

    def size(self):
        return self.width, self.height

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        _l.debug('QBlock got a mouse press')
        button = event.button()
        pos = event.pos()
        if button == Qt.LeftButton:
            event.accept()
            for obj in self.objects:
                if obj.y <= pos.y() < obj.y + obj.height:
                    obj.on_mouse_pressed(button, pos)
                    break
            else:
                _l.debug('Deactivating selected addr and operand')
                self.workspace.instance.selected_addr = None
                self.workspace.instance.selected_operand = None


    def mouseReleaseEvent(self, event):
        button = event.button()
        pos = event.pos()
        if button == Qt.RightButton or button == Qt.LeftButton:
            event.accept()
            for obj in self.objects:
                if obj.y <= pos.y() < obj.y + obj.height:
                    obj.on_mouse_released(button, pos)

    # def mouseDoubleClickEvent(self, event):
    #     button = event.button()
    #     pos = event.pos()
    #     if button == Qt.LeftButton:
    #         for obj in self.objects:
    #             if obj.y <= pos.y() < obj.y + obj.height:
    #                 obj.on_mouse_doubleclicked(button, pos)

    #
    # Initialization
    #

    def _init_widgets(self):

        self.objects.clear()
        block_objects = get_block_objects(self.disasm, self.cfg_nodes, self.func_addr)

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.func_addr, self.disasm_view, self.disasm,
                                    self.infodock, obj, out_branch, self._config, mode=self.mode)
                self.objects.append(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, Label):
                # label
                label = QBlockLabel(obj.addr, obj.text, self._config, self.disasm_view, mode=self.mode)
                self.objects.append(label)
                self.addr_to_labels[obj.addr] = label
            # elif isinstance(obj, PhiVariable):
            #     if not isinstance(obj.variable, SimRegisterVariable):
            #         phivariable = QPhiVariable(self.workspace, self.disasm_view, obj, self._config)
            #         self.objects.append(phivariable)
            # elif isinstance(obj, Variables):
            #     for var in obj.variables:
            #         variable = QVariable(self.workspace, self.disasm_view, var, self._config)
            #         self.objects.append(variable)
        self.layout_widgets()

    def layout_widgets(self):
        raise NotImplementedError

    #
    # Private methods
    #

    def boundingRect(self):
        if self._rect is None:
            self._rect = self._calculate_size()
        assert self._rect is not None
        return self._rect

class QGraphBlock(QBlock):
    MINIMUM_DETAIL_LEVEL = 0.3

    def create_children(self):


    @property
    def mode(self):
        return 'graph'

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_omit_text = lod < QGraphBlock.MINIMUM_DETAIL_LEVEL


        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

        painter.setFont(Conf.code_font)
        # background of the node
        if should_omit_text:
            painter.setBrush(QColor(0xda, 0xda, 0xda))
        else:
            painter.setBrush(QColor(0xfa, 0xfa, 0xfa))
        painter.setPen(QPen(QColor(0xf0, 0xf0, 0xf0), 1.5))
        painter.drawRect(0, 0, self.width, self.height)

        # content

        # if we are two far zoomed out, do not draw the text
        if should_omit_text:
            return
        super().paint(painter, option, widget)
        for obj in self.objects:
            obj.hide()

        y_offset = self.TOP_PADDING

        for obj in self.objects:
            y_offset += self.SPACING

            obj.setPos(self.GRAPH_LEFT_PADDING, y_offset)

            y_offset += obj.boundingRect().height()

    def _calculate_size(self):
        height = len(self.objects) * self._config.disasm_font_height + \
                      (len(self.objects) - 1) * self.SPACING

        height += self.TOP_PADDING
        height += self.BOTTOM_PADDING

        # calculate width

        width = (max([obj.width for obj in self.objects]) if self.objects else 0) + \
                      self.RIGHT_PADDING
        width += self.GRAPH_LEFT_PADDING

        return QRectF(0, 0, width+10, height+10)

class QLinearBlock(QBlock):
    @property
    def mode(self):
        return 'linear'

    def layout_widgets(self):
        y_offset = 0

        for obj in self.objects:
            y_offset += self.SPACING

            obj.x = 0
            obj.y = y_offset
            if hasattr(obj, '_layout_operands'):
                obj._layout_operands()

            y_offset += obj.height

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        _l.debug('Painting linear block')
        y_offset = 0

        self.layout_widgets()
        for obj in self.objects:
            obj.paint(painter)

    def _calculate_size(self):
        height = len(self.objects) * self._config.disasm_font_height + \
                      (len(self.objects) - 1) * self.SPACING

        # calculate width

        width = (max([obj.width for obj in self.objects]) if self.objects else 0) + \
                      self.RIGHT_PADDING

        return QRectF(0, 0, width, height)
