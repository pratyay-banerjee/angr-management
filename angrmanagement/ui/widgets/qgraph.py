import logging

from PySide2.QtWidgets import QGraphicsScene, QGraphicsView, QStyleOptionGraphicsItem
from PySide2.QtGui import QPainter, QKeyEvent, QMouseEvent, QImage
from PySide2.QtCore import Qt, QSize, Signal, QPoint, QEvent, QRectF, QMarginsF

from ...data.instance import ObjectContainer

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

class QZoomingGraphicsView(QGraphicsView):

    def __init__(self, parent):
        super(QZoomingGraphicsView, self).__init__(parent)

        self._is_dragging = False
        self._is_mouse_pressed = False

        self._mouse_press_event = None
        self._last_coords = (0.0, 0.0)#None

        self.setTransformationAnchor(QGraphicsView.NoAnchor)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)

        # scroll bars are useless when the scene is near-infinite
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

    def _reset_scene(self):
        width = 1000000 # a ludicrously large number, to emulate infinite panning
        self.scene = QGraphicsScene(- (width / 2), - (width / 2), width, width)

    def sizeHint(self):
        return QSize(300, 300)

    def save_image_to(self, path, top_margin=50, bottom_margin=50, left_margin=50, right_margin=50):

        margins = QMarginsF(left_margin, top_margin, right_margin, bottom_margin)

        oldRect = self.scene.sceneRect()
        minRect = self.scene.itemsBoundingRect()
        imgRect = minRect.marginsAdded(margins)


        image = QImage(imgRect.size().toSize(), QImage.Format_ARGB32)
        image.fill(Qt.white)
        painter = QPainter(image)

        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

        self.scene.setSceneRect(imgRect)
        self.scene.render(painter)
        image.save(path)
        painter.end()
        self.scene.setSceneRect(oldRect)


    def wheelEvent(self, event):
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            lod = QStyleOptionGraphicsItem.levelOfDetailFromTransform(self.transform())
            zoomInFactor = 1.25
            zoomOutFactor = 1 / zoomInFactor

            # Save the scene pos
            oldPos = self.mapToScene(event.pos())

            # Zoom
            if event.delta() > 0:
                zoomFactor = zoomInFactor
            else:
                zoomFactor = zoomOutFactor
                # limit the scroll out limit for usability
                if lod < 0.015:
                    return
            self.scale(zoomFactor, zoomFactor)

            # Get the new position
            newPos = self.mapToScene(event.pos())

            # Move scene to old position
            delta = newPos - oldPos
            self.translate(delta.x(), delta.y())
        else:
            super(QZoomingGraphicsView, self).wheelEvent(event)

    def event(self, event):
        """
        Reimplemented to capture the Tab keypress event.
        """

        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.key_pressed.emit(event)
            return True

        return super(QZoomingGraphicsView, self).event(event)

    def _save_mouse_press_event(self, event):
        self._mouse_press_event = QMouseEvent(event.type(),
                                              event.pos(),
                                              event.globalPos(),
                                              event.button(),
                                              event.buttons(),
                                              event.modifiers())

    def _save_last_coords(self, event):
        pos = self.mapToScene(event.pos())
        self._last_coords = (pos.x(), pos.y())

    def mousePressEvent(self, event):
        if self._allow_dragging and event.button() == Qt.LeftButton:

            self._is_mouse_pressed = True
            self._is_dragging = False

            self._save_mouse_press_event(event)
            self._save_last_coords(event)

    def mouseMoveEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if self._is_mouse_pressed:
            self._is_dragging = True
            pos = self.mapToScene(event.pos())

            self.viewport().setCursor(Qt.ClosedHandCursor)

            delta = (pos.x() - self._last_coords[0], pos.y() - self._last_coords[1])
            self.translate(*delta)
            self._save_last_coords(event)
            event.accept()

    def mouseReleaseEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            if self._is_dragging:
                self.viewport().setCursor(Qt.ArrowCursor)
                event.accept()
            else:
                super().mousePressEvent(self._mouse_press_event)
                super().mouseReleaseEvent(event)
            self._is_mouse_pressed = False
            self._is_dragging = False


class QBaseGraph(QZoomingGraphicsView):

    def __init__(self, workspace, parent=None, allow_dragging=True):
        super(QBaseGraph, self).__init__(parent)

        self.workspace = workspace
        self.scene = None
        self._edge_paths = []
        self.blocks = set()

        self.selected_insns = ObjectContainer(set(), 'The currently selected instructions')
        self.selected_operands = set()
        self._insn_addr_to_block = {}
        self._allow_dragging = allow_dragging

    def request_relayout(self):
        raise NotImplementedError()

    def update_label(self, label_addr, is_renaming=False):
        # if it's just a renaming, we simply update the text of the label
        if is_renaming:
            if label_addr in self._insn_addr_to_block:
                block = self._insn_addr_to_block[label_addr]
                block.update_label(label_addr)

            else:
                # umm not sure what's going wrong
                _l.error('Label address %#x is not found in the current function.', label_addr)

        else:
            self.reload()

    def update_comment(self, comment_addr, comment_text):
        if comment_addr in self._insn_addr_to_block:
            block = self._insn_addr_to_block[comment_addr]
            insn = block.addr_to_insns[comment_addr]
            if insn:
                insn.set_comment(comment_text)
        else:
            # umm not sure what's going wrong
            _l.error('Label address %#x is not found in the current function.', comment_addr)

        self.reload()

    def select_instruction(self, insn_addr, unique=True):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            # the instruction does not belong to the current function
            return

        if insn_addr not in self.selected_insns:
            if unique:
                # unselect existing ones
                self.unselect_all_instructions()
                self.selected_insns.add(insn_addr)
            else:
                self.selected_insns.add(insn_addr)

            block.addr_to_insns[insn_addr].select()

        # Notify subscribers BEFORE we update the viewport so they can make any further changes
        #self.selected_insns.am_event(graph=self, addr=insn_addr, block=block)
        self.viewport().update()

    def unselect_instruction(self, insn_addr):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if insn_addr in self.selected_insns:
            self.selected_insns.remove(insn_addr)

            block.addr_to_insns[insn_addr].unselect()

        self.viewport().update()

    def unselect_all_instructions(self):
        for insn_addr in self.selected_insns.copy():
            self.unselect_instruction(insn_addr)

    def select_operand(self, insn_addr, operand_idx, unique=True):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            # the instruction does not belong to the current function
            return

        if (insn_addr, operand_idx) not in self.selected_operands:
            if unique:
                # unselect existing ones
                self.unselect_all_operands()
                self.selected_operands = { (insn_addr, operand_idx) }
            else:
                self.selected_operands.add((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].select_operand(operand_idx)

        self.viewport().update()

    def unselect_operand(self, insn_addr, operand_idx):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if (insn_addr, operand_idx) in self.selected_operands:
            self.selected_operands.remove((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].unselect_operand(operand_idx)

        self.viewport().update()

    def unselect_all_operands(self):
        for insn_addr, operand_idx in self.selected_operands.copy():
            self.unselect_operand(insn_addr, operand_idx)

    def show_selected(self):
        if self.selected_insns:
            addr = next(iter(self.selected_insns))
            self.show_instruction(addr)

    def show_instruction(self, insn_addr):
        raise NotImplementedError

    #
    # Event handlers
    #

    #
    # Private methods
    #


    def _set_pos(self, widget, coord):
        """
        Set the position of a widget in the scene with QTransform.
        Solves this problem:
        http://stackoverflow.com/questions/23342039/qgraphicsproxywidgetsetposqreal-x-qreal-y-doesnt-place-correctly-in-a-qgra

        :param widget: The widget to set position.
        :param coord: The new coordinate.
        :return: None
        """
        widget.resetTransform()
        trans = widget.transform()
        widget.setTransform(trans.translate(coord.x(), coord.y()))

    def _clear_insn_addr_block_mapping(self):
        self._insn_addr_to_block.clear()

    def _add_insn_addr_block_mapping(self, insn_addr, block):
        self._insn_addr_to_block[insn_addr] = block
