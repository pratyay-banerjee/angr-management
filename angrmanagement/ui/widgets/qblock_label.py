
from PySide2.QtWidgets import QGraphicsItem, QGraphicsTextItem
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt, QRectF

from .qgraph_object import QCachedGraphicsItem


class QBlockLabel(QCachedGraphicsItem):

    LINEAR_LABEL_OFFSET = 10

    def __init__(self, addr, text, config, disasm_view, mode='graph', parent=None):
        super().__init__(parent=parent)

        self.addr = addr
        self.text = text
        self.mode = mode

        self._config = config
        self._disasm_view = disasm_view

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
        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.code_font)
        painter.setPen(Qt.blue)
        painter.drawText(0, self._config.disasm_font_ascent, self.text)

    def _boundingRect(self):
        return QRectF(0, 0, self._config.disasm_font_metrics.width(self.text), self._config.disasm_font_height)
