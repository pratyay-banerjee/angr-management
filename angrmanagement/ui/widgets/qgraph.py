import logging

from PySide2.QtWidgets import QGraphicsScene, QGraphicsView, QStyleOptionGraphicsItem
from PySide2.QtGui import QPainter, QKeyEvent, QMouseEvent, QImage, QVector2D
from PySide2.QtCore import Qt, QSize, Signal, QPoint, QEvent, QRectF, QMarginsF, QObject

from ...data.instance import ObjectContainer

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

class QSaveableGraphicsView(QGraphicsView):

    def save_image_to(self, path, top_margin=50, bottom_margin=50, left_margin=50, right_margin=50):

        margins = QMarginsF(left_margin, top_margin, right_margin, bottom_margin)

        oldRect = self.scene().sceneRect()
        minRect = self.scene().itemsBoundingRect()
        imgRect = minRect.marginsAdded(margins)


        image = QImage(imgRect.size().toSize(), QImage.Format_ARGB32)
        image.fill(Qt.white)
        painter = QPainter(image)

        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

        self.scene().setSceneRect(imgRect)
        self.scene().render(painter)
        image.save(path)
        painter.end()
        self.scene().setSceneRect(oldRect)


class QZoomableDraggableGraphicsView(QSaveableGraphicsView):

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self._is_dragging = False
        self._is_mouse_pressed = False

        self._last_coords = None
        self._last_screen_pos = None

        self.setTransformationAnchor(QGraphicsView.NoAnchor)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)

        # scroll bars are useless when the scene is near-infinite
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

    def _initial_position(self):
        raise NotImplementedError

    def _reset_view(self):
        self.resetMatrix()
        self.centerOn(self._initial_position())

    def _reset_scene(self):
        if self.scene() is None:
            width = 1000000 # a ludicrously large number, to emulate infinite panning
            scene = QGraphicsScene(- (width / 2), - (width / 2), width, width)
            self.setScene(scene)
        else:
            self.scene().clear()

    def sizeHint(self): #pylint: disable=no-self-use
        return QSize(300, 300)


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
            super().wheelEvent(event)

    def _save_last_coords(self, event):
        pos = self.mapToScene(event.pos())
        self._last_coords = (pos.x(), pos.y())
        self._last_screen_pos = event.pos()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Equal:
            try:
                self._reset_view()
            except NotImplementedError:
                _l.warning('%s does not implement _initial_position', type(self).__name__)
        else:
            super().keyPressEvent(event)

    def mousePressEvent(self, event):
        _l.debug('Received press')
        if event.button() == Qt.LeftButton:

            self._is_mouse_pressed = True
            self._is_dragging = False

            self._save_last_coords(event)

    def mouseMoveEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        SENSITIVITY = 1.0
        if self._is_mouse_pressed:
            mouse_delta = QVector2D(event.pos() - self._last_screen_pos).length()
            if mouse_delta > SENSITIVITY:
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
                pressy = QMouseEvent(QEvent.MouseButtonPress,
                                     event.pos(),
                                     event.globalPos(),
                                     event.button(),
                                     event.buttons(),
                                     event.modifiers())
                super().mousePressEvent(pressy)
                super().mouseReleaseEvent(event)
            self._is_mouse_pressed = False
            self._is_dragging = False


class QAssemblyLevelGraph(QZoomableDraggableGraphicsView):
    def __init__(self, workspace, parent=None):
        super().__init__(parent=parent)
        self.workspace = workspace
        self._edge_paths = []
        self.blocks = set()

        self.selected_insns = ObjectContainer(set(), 'The currently selected instructions')
        self.selected_operands = set()
        self._insn_addr_to_block = {}


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
            block.update()

        # Notify subscribers BEFORE we update the viewport so they can make any further changes
        #self.selected_insns.am_event(graph=self, addr=insn_addr, block=block)
        #self.viewport().update()
        #self.reload()

    def unselect_instruction(self, insn_addr):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if insn_addr in self.selected_insns:
            self.selected_insns.remove(insn_addr)

            block.addr_to_insns[insn_addr].unselect()
        block.update()

        #self.viewport().update()
        #self.update()
        _l.debug('Finished the reload')

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

        self.scene().update(self.sceneRect())

    def reload(self):
        raise NotImplementedError

    def unselect_operand(self, insn_addr, operand_idx):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if (insn_addr, operand_idx) in self.selected_operands:
            self.selected_operands.remove((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].unselect_operand(operand_idx)

        self.scene().update(self.sceneRect())

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


    def _clear_insn_addr_block_mapping(self):
        self._insn_addr_to_block.clear()

    def _add_insn_addr_block_mapping(self, insn_addr, block):
        self._insn_addr_to_block[insn_addr] = block
