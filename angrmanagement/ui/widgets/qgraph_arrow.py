
from PySide2.QtWidgets import QGraphicsItem
from PySide2.QtGui import QPen, QBrush, QColor, QPainter
from PySide2.QtCore import QPointF, QRectF
import functools

import random
from ...utils.edge import EdgeSort

class QGraphArrow(QGraphicsItem):
    def __init__(self, edge, parent=None):
        super().__init__(parent)

        self.edge = edge
        self.rect = None
        self._start = QPointF(*self.edge.coordinates[0])
        self.coords = [self.create_point(c) for c in self.edge.coordinates]
        self.start = self.coords[0]
        self.end = self.coords[-1]

        if self.edge.sort == EdgeSort.BACK_EDGE:
            # it's a back edge
            # Honey
            self.color = QColor(0xf9, 0xd5, 0x77)
        elif self.edge.sort == EdgeSort.TRUE_BRANCH:
            # True branch
            # Aqar
            self.color = QColor(0x79, 0xcc, 0xcd)
        elif self.edge.sort == EdgeSort.FALSE_BRANCH:
            # False branch
            # Tomato
            self.color = QColor(0xf1, 0x66, 0x64)
        else:
            # Dark Gray
            self.color = QColor(0x56, 0x5a, 0x5c)
        self.arrow = [QPointF(self.end.x() - 3, self.end.y()), QPointF(self.end.x() + 3, self.end.y()),
                 QPointF(self.end.x(), self.end.y() + 6)]

    def create_point(self, stuff):
        return QPointF(*stuff) - self._start


    def paint(self, painter, option, widget):
        lod = option.levelOfDetailFromTransform(painter.worldTransform())

        pen = QPen(self.color)
        pen.setWidth(2)
        painter.setPen(pen)

        painter.drawPolyline(self.coords)
        # for segment_start, segment_end in zip(self.coords, self.coords[1:]):
        #     painter.drawPolyline((segment_start, segment_end))

        # arrow
        # end_point = self.mapToScene(*edges[-1])
        if lod < 0.3:
            return
        brush = QBrush(self.color)
        painter.setBrush(brush)
        painter.drawPolygon(self.arrow)

    def boundingRect(self):
        if self.rect is None:
            minx = None
            maxx = None
            miny = None
            maxy = None
            for pt in self.coords:
                y = pt.y()
                x = pt.x()
                if minx is None or x < minx:
                    minx = x
                if maxx is None or x > maxx:
                    maxx = x
                if miny is None or y < miny:
                    miny = y
                if maxy is None or y > maxy:
                    maxy = y
            self.rect = QRectF(QPointF(minx-10, miny-10), QPointF(maxx+10, maxy+10))
        else:
            return self.rect
