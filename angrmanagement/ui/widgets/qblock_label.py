
from PySide2.QtWidgets import QGraphicsItem, QGraphicsTextItem
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt, QRectF

from .qgraph_object import QGraphObject


class QBlockLabel(QGraphicsItem):

    LINEAR_LABEL_OFFSET = 10

    def __init__(self, addr, text, config, disasm_view, mode='graph', parent=None):
        super().__init__(parent=parent)

        self.addr = addr
        self.text = text
        self.mode = mode

        self._config = config
        self._disasm_view = disasm_view

        child = QGraphicsTextItem(self.text, parent=self)
        child.setPos(0, 0)
        child.setDefaultTextColor(Qt.blue)

    @property
    def label(self):
        return self.text

    @label.setter
    def label(self, v):
        self._clear_size()
        self.text = v

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    def size(self):
        return self.width, self.height

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        pass

    def _paint_linear(self, painter):

        x = self.x

        if self._disasm_view.show_address:
            # Address
            addr_text = "%08x" % self.addr

            painter.setPen(Qt.black)
            painter.drawText(self.x, self.y + self._config.disasm_font_ascent, addr_text)

            x += len(addr_text) * self._config.disasm_font_width
            x += self.LINEAR_LABEL_OFFSET

        # Label
        painter.setPen(Qt.blue)
        painter.drawText(x, self.y + self._config.disasm_font_ascent, self.text)

    def _paint_graph(self, painter):
        painter.setPen(Qt.blue)
        painter.drawText(self.x, self.y + self._config.disasm_font_ascent, self.text)

    def _clear_size(self):
        self._width = None
        self._height = None

    def _update_size(self):
        self._width = self._config.disasm_font_width * len(self.text)
        self._height = self._config.disasm_font_height

    def boundingRect(self):
        self._update_size()
        return QRectF(0, 0, self._width, self._height)
