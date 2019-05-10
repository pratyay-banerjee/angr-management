from functools import wraps
import logging

from PySide2.QtCore import QPointF, QRectF, Qt, QPoint, QSize
from PySide2.QtGui import QPainter, QBrush, QColor, QMouseEvent, QResizeEvent, QPen, QImage
from PySide2.QtWidgets import QApplication

from ...config import Conf
from ...utils import get_out_branches
from ...utils.graph_layouter import GraphLayouter
from ...utils.cfg import categorize_edges
from ...utils.edge import EdgeSort
from .qblock import QBlock
from .qgraph_arrow import QGraphArrow
from .qgraph import QBaseGraph

l = logging.getLogger('ui.widgets.qflow_graph')
#l.setLevel(logging.DEBUG)

def timeit(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        import time
        start = time.time()
        r = f(*args, **kwargs)
        elapsed = time.time() - start
        print("%s takes %f sec." % (f.__name__, elapsed))

        return r
    return decorator


class QDisasmGraph(QBaseGraph):

    XSPACE = 40
    YSPACE = 40
    LEFT_PADDING = 1000
    TOP_PADDING = 1000

    def __init__(self, workspace, parent=None):
        super(QDisasmGraph, self).__init__(workspace, parent=parent)

        self.disassembly_view = parent
        self.disasm = None
        self.variable_manager = None

        self._function_graph = None

        self._edges = None

        #self.key_pressed.connect(self._on_keypressed_event)
        #self.key_released.connect(self._on_keyreleased_event)
        self.blocks = []

    #
    # Properties
    #

    @property
    def function_graph(self):
        return self._function_graph

    @function_graph.setter
    def function_graph(self, v):

        if v is not self._function_graph:
            self._function_graph = v

            self.reload()

    @property
    def infodock(self):
        return self.disassembly_view.infodock

    @property
    def induction_variable_analysis(self):
        return self.infodock.induction_variable_analysis

    @induction_variable_analysis.setter
    def induction_variable_analysis(self, v):
        self.infodock.induction_variable_analysis = v

    #
    # Public methods
    #

    def reload(self):
        self._reset_scene()
        self.disasm = self.workspace.instance.project.analyses.Disassembly(function=self._function_graph.function)
        self.workspace.view_manager.first_view_in_category('console').push_namespace({
            'disasm': self.disasm,
        })

        self._clear_insn_addr_block_mapping()
        self.blocks.clear()


        supergraph = self._function_graph.supergraph
        for n in supergraph.nodes():
            block = QBlock(self.workspace, self._function_graph.function.addr, self.disassembly_view, self.disasm,
                           self.infodock, n.addr, n.cfg_nodes, get_out_branches(n)
                           )
            self.scene.addItem(block)
            self.blocks.append(block)

            for insn_addr in block.addr_to_insns.keys():
                self._add_insn_addr_block_mapping(insn_addr, block)

        self.request_relayout()
        self.setScene(self.scene)
        self.show()

    def refresh(self):
        pass

    def save_image_to(self, path):
        pass

    def remove_block(self, block):
        pass

    #
    # Event handlers
    #

    # def mousePressEvent(self, event):
    #     """

    #     :param QMouseEvent event:
    #     :return:
    #     """

    #     btn = event.button()
    #     if btn == Qt.LeftButton:
    #         block = self._get_block_by_pos(event.pos())
    #         if block is not None:
    #             # clicking on a block
    #             block.on_mouse_pressed(event.button(), self._to_graph_pos(event.pos()))
    #             event.accept()
    #             return
    #     elif btn == Qt.ForwardButton:
    #         # Jump forward
    #         self.disassembly_view.jump_forward()
    #         return
    #     elif btn == Qt.BackButton:
    #         # Jump backward
    #         self.disassembly_view.jump_back()
    #         return

    #     super(QDisasmGraph, self).mousePressEvent(event)

    # def mouseReleaseEvent(self, event):
    #     """

    #     :param QMouseEvent event:
    #     :return:
    #     """

    #     if event.button() == Qt.RightButton:
    #         block = self._get_block_by_pos(event.pos())
    #         if block is not None:
    #             block.on_mouse_released(event.button(), self._to_graph_pos(event.pos()))
    #         event.accept()
    #         return

    #     super(QDisasmGraph, self).mouseReleaseEvent(event)

    # def mouseDoubleClickEvent(self, event):
    #     """

    #     :param QMouseEvent event:
    #     :return:
    #     """

    #     if event.button() == Qt.LeftButton:
    #         block = self._get_block_by_pos(event.pos())
    #         if block is not None:
    #             block.on_mouse_doubleclicked(event.button(), self._to_graph_pos(event.pos()))
    #         event.accept()
    #         return True

    # def _on_keypressed_event(self, key_event):

    #     key = key_event.key()

    #     if key == Qt.Key_G:
    #         # jump to window
    #         self.disassembly_view.popup_jumpto_dialog()
    #         return True
    #     elif key == Qt.Key_N:
    #         # rename a label
    #         self.disassembly_view.popup_rename_label_dialog()
    #         return True
    #     elif key == Qt.Key_X:
    #         # XRef

    #         # get the variable
    #         if self.selected_operands:
    #             ins_addr, operand_idx = next(iter(self.selected_operands))
    #             block = self._insn_addr_to_block.get(ins_addr, None)
    #             if block is not None:
    #                 operand = block.addr_to_insns[ins_addr].get_operand(operand_idx)
    #                 if operand is not None and operand.variable is not None:
    #                     self.disassembly_view.popup_xref_dialog(operand.variable)
    #         return True
    #     elif key == Qt.Key_Escape or (key == Qt.Key_Left and QApplication.keyboardModifiers() & Qt.ALT != 0):
    #         # jump back
    #         self.disassembly_view.jump_back()
    #         return True
    #     elif key == Qt.Key_Right and QApplication.keyboardModifiers() & Qt.ALT != 0:
    #         # jump forward
    #         self.disassembly_view.jump_forward()
    #         return True

    #     elif key == Qt.Key_A:
    #         # switch between highlight mode
    #         self.disassembly_view.toggle_smart_highlighting(not self.infodock.smart_highlighting)
    #         return True

    #     elif key == Qt.Key_Tab:
    #         # decompile
    #         self.disassembly_view.decompile_current_function()
    #         return True

    #     elif key == Qt.Key_Semicolon:
    #         # add comment
    #         self.disassembly_view.popup_comment_dialog()
    #         return True

    #     return False

    # def _on_keyreleased_event(self, key_event):

    #     key = key_event.key()

    #     if key == Qt.Key_Space:
    #         # switch to linear view
    #         self.disassembly_view.display_linear_viewer()

    #         return True

    #     return False

    #
    # Layout
    #

    def _graph_size(self):

        width, height = 0, 0

        for block in self.blocks:
            if block.x + block.width > width:
                width = block.x + block.width
            if block.y + block.height > height:
                height = block.y + block.height

        # TODO: Check all edges as well

        return QSize(width, height)

    def _layout_graph(self):

        node_sizes = {}
        node_map = {}
        for block in self.blocks:
            node_map[block.addr] = block
        for node in self.function_graph.supergraph.nodes():
            block = node_map[node.addr]
            node_sizes[node] = block.width, block.height
        gl = GraphLayouter(self.function_graph.supergraph, node_sizes)

        nodes = { }
        for node, coords in gl.node_coordinates.items():
            nodes[node.addr] = coords

        return nodes, gl.edges

    def request_relayout(self, ensure_visible=True):

        node_coords, edges = self._layout_graph()

        self._edges = edges

        categorize_edges(self.disasm, edges)

        if not node_coords:
            print("Failed to get node_coords")
            return

        min_x, max_x, min_y, max_y = 0, 0, 0, 0

        # layout nodes
        for block in self.blocks:
            x, y = node_coords[block.addr]
            l.debug('Placing block (addr 0x%x) at (%d, %d)', block.addr, x, y)
            block.setPos(x, y)

        for edge in self._edges:
            arrow = QGraphArrow(edge)
            self.scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))

        # scrollbars
        #self.horizontalScrollBar().setRange(min_x, max_x)
        #self.verticalScrollBar().setRange(min_y, max_y)

        #self.setSceneRect(QRectF(min_x, min_y, width, height))

        #self.viewport().update()

        #self._update_size()

        # if ensure_visible:
        #     if self.selected_insns:
        #         self.show_selected()
        #     else:
        #         self.show_instruction(self._function_graph.function.addr, centering=True, use_block_pos=True)

    def show_instruction(self, insn_addr, centering=False, use_block_pos=False):
        pass
